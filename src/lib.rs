use crate::phi_loop_source::{PhiLoopSource, match_phi_loop_sources};
use binaryninja::{
    architecture::CoreRegister,
    binary_view::BinaryViewExt as _,
    logger::Logger,
    low_level_il::{
        LowLevelILRegisterKind, LowLevelILSSARegisterKind,
        function::{FunctionForm, FunctionMutability, LowLevelILFunction, Mutable, NonSSA, SSA},
        instruction::LowLevelILInstruction,
        lifting::LowLevelILLabel,
    },
    rc::Ref,
    workflow::{Activity, AnalysisContext, Workflow},
};
use bn_bdash_extras::{
    activity,
    llil::{
        BinaryExpression,
        ExpressionKind::{Const, RegSsa},
        Instruction,
        InstructionKind::If,
        macros::InstrMatch,
        require_full_register,
    },
};

mod phi_loop_source;

fn tag_type_for_view(
    view: &binaryninja::binary_view::BinaryView,
) -> Ref<binaryninja::tags::TagType> {
    view.tag_type_by_name("armv7 eq")
        .unwrap_or_else(|| view.create_tag_type("armv7 eq", "7eq"))
}

fn convert_instructions_to_nops<'func>(
    llil: &'func Ref<LowLevelILFunction<Mutable, NonSSA>>,
    instrs: &[LowLevelILInstruction<'func, Mutable, SSA>],
) {
    for inst in instrs.iter().map(|i| i.non_ssa_form(llil)) {
        llil.set_current_address(inst.address());
        if let If(_, _, false_target) = inst.into() {
            unsafe {
                let mut label = LowLevelILLabel::new();
                label.operand = false_target.index.0;
                llil.replace_expression(inst.expr_idx(), llil.goto(&mut label));
            }
        } else {
            unsafe {
                llil.replace_expression(inst.expr_idx(), llil.nop());
            }
        }
    }
}

#[derive(InstrMatch, Debug)]
#[pattern(instr @ SetRegSsa(dest, Lsr(RegSsa(source), Const(5))))]
struct SetToLsrBy5<'func, M, F>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    instr: Instruction<'func, M, F>,
    dest: LowLevelILSSARegisterKind<CoreRegister>,
    source: LowLevelILSSARegisterKind<CoreRegister>,
}

#[derive(InstrMatch, Debug)]
#[pattern(SetRegSsa(_, Sub(Const(0x20), RegSsa(source))))]
struct SetToSubFrom32 {
    source: LowLevelILSSARegisterKind<CoreRegister>,
}

#[derive(InstrMatch, Debug)]
#[pattern(instr @ SetRegSsa(_, Const(0)))]
struct SetToConstZero<'func, M, F>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    instr: LowLevelILInstruction<'func, M, F>,
}

#[derive(InstrMatch, Debug)]
#[pattern(instr @ SetRegSsa(_, Add(RegSsa(_), Const(1))))]
struct Increment<'func, M, F>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    instr: LowLevelILInstruction<'func, M, F>,
}

#[derive(InstrMatch, Debug)]
#[pattern(instr @ SetRegSsa(_, Lsr(RegSsa(_), Const(1))))]
struct SetToLsrBy1<'func, M, F>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    instr: LowLevelILInstruction<'func, M, F>,
}

#[derive(InstrMatch, Debug)]
#[pattern(instr @ SetRegSsa(_, Sub(op)))]
struct SetToSub<'func, M, F>
where
    M: FunctionMutability,
    F: FunctionForm,
{
    instr: Instruction<'func, M, F>,
    op: Box<BinaryExpression<'func, M, F>>,
}

#[derive(Debug)]
struct MatchedClzLsr<'func> {
    // Original instruction
    instr: LowLevelILInstruction<'func, Mutable, SSA>,
    llil: &'func Ref<LowLevelILFunction<Mutable, NonSSA>>,

    // Info about the assignment we're rewriting
    dest_reg: LowLevelILRegisterKind<CoreRegister>,
    assignment_size: usize,

    // Instructions to be replaced with no-ops
    instrs_to_nop: Vec<LowLevelILInstruction<'func, Mutable, SSA>>,

    // The specific pattern matched
    pattern: ClzLsrPattern<'func>,
}

impl MatchedClzLsr<'_> {
    pub fn description(&self) -> &'static str {
        match self.pattern {
            ClzLsrPattern::Equality { .. } => "clz/lsr into equality test",
            ClzLsrPattern::LogicalNegation { .. } => "clz/lsr into logical negation",
        }
    }

    fn rewrite(&self) {
        match self.pattern {
            ClzLsrPattern::Equality { .. } => rewrite_equality_test(self),
            ClzLsrPattern::LogicalNegation { .. } => rewrite_logical_negation(self),
        }
    }
}

#[derive(Debug)]
enum ClzLsrPattern<'func> {
    Equality {
        sub: SetToSub<'func, Mutable, SSA>,
    },
    LogicalNegation {
        orig_expr_reg: LowLevelILRegisterKind<CoreRegister>,
        orig_expr_size: usize,
    },
}

fn try_match_clz_lsr<'func>(
    instr: &'func LowLevelILInstruction<'func, Mutable, SSA>,
    llil: &'func Ref<LowLevelILFunction<Mutable, NonSSA>>,
    ssa: &'func Ref<LowLevelILFunction<Mutable, SSA>>,
) -> Option<MatchedClzLsr<'func>> {
    // lsr_dst_reg = shifted_reg >> 5
    let lsr_by_5 = SetToLsrBy5::try_from(*instr).ok()?;
    let shifted_reg_def = ssa.get_ssa_register_definition(&lsr_by_5.source)?;

    // shifted_reg = 0x20 - sub_rhs_reg
    let sub_from_32 = SetToSubFrom32::try_from(shifted_reg_def).ok()?;
    let sub_from_32_source_def = ssa.get_ssa_register_definition(&sub_from_32.source)?;

    // sub_rhs_reg = phi(a, b)
    let PhiLoopSource::<_, SetToConstZero<_, _>, Increment<_, _>> {
        matched: (init, increment),
        ..
    } = match_phi_loop_sources(&sub_from_32_source_def, ssa)?;

    // The clz loop has been identified. Look within the same basic block to find the expression
    // whose bits are being counted. This will be a phi node with an incoming def that is a >> 1.
    let expr_being_counted_phi: PhiLoopSource<_, SetToLsrBy1<'_, _, _>, Instruction<'_, _, _>> =
        sub_from_32_source_def
            .basic_block()?
            .iter()
            .find_map(|instr| match_phi_loop_sources(&instr, ssa))?;
    let (ref lsr_by_1, ref expr_being_counted) = expr_being_counted_phi.matched;

    // If the expression being counted was a `SetRegSsa(_, Sub(..))` then we can rewrite it
    // as an equality test. Otherwise, we rewrite it as a logical negation.
    let pattern = if let Ok(sub) = SetToSub::try_from(expr_being_counted.inner) {
        ClzLsrPattern::Equality { sub }
    } else {
        let (_, orig_expr, orig_expr_reg) = expr_being_counted_phi.right();

        ClzLsrPattern::LogicalNegation {
            orig_expr_reg: require_full_register(orig_expr_reg, &orig_expr)?,
            orig_expr_size: orig_expr.size()?,
        }
    };

    Some(MatchedClzLsr {
        instr: *instr,
        llil,
        assignment_size: lsr_by_5.instr.size().expect("SetRegSsa should have a size"),
        dest_reg: require_full_register(lsr_by_5.dest, &lsr_by_5.instr)?,
        instrs_to_nop: vec![
            shifted_reg_def,
            sub_from_32_source_def,
            init.instr,
            increment.instr,
            lsr_by_1.instr,
        ],
        pattern,
    })
}

fn rewrite_equality_test(matched: &MatchedClzLsr<'_>) {
    let ClzLsrPattern::Equality { sub } = &matched.pattern else {
        unreachable!();
    };
    let (lhs, rhs) = (&sub.op.0, &sub.op.1);
    log::debug!(
        "{:#0x} {}: Rewriting {}:\n\tLHS: {lhs:0x?}\n\tRHS: {rhs:0x?}",
        matched.instr.address(),
        matched.instr.index,
        matched.description(),
    );

    unsafe {
        matched.llil.set_current_address(matched.instr.address());
        matched.llil.replace_expression(
            matched.instr.non_ssa_form(matched.llil).expr_idx(),
            matched.llil.set_reg(
                matched.assignment_size,
                matched.dest_reg,
                matched.llil.cmp_e(
                    sub.instr.size().expect("SetRegSsa should have a size"),
                    lhs.inner.non_ssa_form(matched.llil),
                    rhs.inner.non_ssa_form(matched.llil),
                ),
            ),
        );
    }

    convert_instructions_to_nops(matched.llil, &matched.instrs_to_nop);
    convert_instructions_to_nops(matched.llil, &[sub.instr.inner]);
}

fn rewrite_logical_negation(matched: &MatchedClzLsr<'_>) {
    let ClzLsrPattern::LogicalNegation {
        orig_expr_reg,
        orig_expr_size,
    } = matched.pattern
    else {
        unreachable!()
    };

    log::debug!(
        "{:#0x} {}: Rewriting {}",
        matched.instr.address(),
        matched.instr.index,
        matched.description()
    );

    let orig_expr_non_ssa = matched.llil.reg(orig_expr_size, orig_expr_reg);

    unsafe {
        matched.llil.set_current_address(matched.instr.address());
        matched.llil.replace_expression(
            matched.instr.non_ssa_form(matched.llil).expr_idx(),
            matched.llil.set_reg(
                matched.assignment_size,
                matched.dest_reg,
                matched.llil.cmp_e(
                    orig_expr_size,
                    orig_expr_non_ssa,
                    matched.llil.const_int(orig_expr_size, 0),
                ),
            ),
        );
    }
    convert_instructions_to_nops(matched.llil, &matched.instrs_to_nop);
}

fn process_armv7_equality_test(analysis_context: &AnalysisContext) {
    let Some(llil) = (unsafe { analysis_context.llil_function() }) else {
        return;
    };
    let Some(ssa) = llil.ssa_form() else { return };

    let mut did_update = false;
    for block in &ssa.basic_blocks() {
        for instr in block.iter() {
            let Some(matched) = try_match_clz_lsr(&instr, &llil, &ssa) else {
                continue;
            };

            matched.rewrite();

            analysis_context.function().add_tag(
                &tag_type_for_view(&analysis_context.view()),
                &format!("Rewrote {}", matched.description()),
                Some(instr.address()),
                false,
                None,
            );
            did_update = true;
        }
    }

    if did_update {
        llil.generate_ssa_form();
        llil.finalized();
    }
}

fn register_activity(workflow: &Workflow) {
    if !workflow.registered() {
        log::debug!(
            "Skipping activity registration for workflow {} as it is not registered",
            workflow.name()
        );
        return;
    }

    let workflow = workflow.clone_to(&workflow.name());
    let config = activity::Config::action(
        "bdash.armv7-equality-test",
        "Rewrite clz / lsr to equality tests",
        "Rewrite clz / lsr sequences generated by the compiler to equality tests",
    );
    let activity = Activity::new_with_action(&config.to_string(), process_armv7_equality_test);
    workflow.register_activity(&activity).unwrap();
    workflow.insert("core.function.generateMediumLevelIL", [activity.name()]);
    workflow.register().unwrap();
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "C" fn CorePluginInit() -> bool {
    Logger::new("armv7 eq")
        .with_level(log::LevelFilter::Debug)
        .init();

    register_activity(&Workflow::instance("core.function.metaAnalysis"));

    true
}
