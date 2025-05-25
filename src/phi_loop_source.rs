use binaryninja::{
    architecture::CoreRegister,
    low_level_il::{
        LowLevelILSSARegisterKind,
        function::{FunctionMutability, LowLevelILFunction, SSA},
        instruction::LowLevelILInstruction,
    },
    rc::Ref,
};
use bn_bdash_extras::llil::{
    Instruction,
    macros::{InstrMatch, try_let_instr},
};

#[derive(InstrMatch, Debug)]
#[pattern(SetRegSsa(_, RegSsa(source)))]
struct CopyReg {
    source: LowLevelILSSARegisterKind<CoreRegister>,
}

/// Follow any `SetRegSsa(_, RegSsa(..))` copy chains to the original SSA def.
fn resolve_set_reg_ssa_to_reg_ssa_chain<'func, M>(
    ssa: &'func Ref<LowLevelILFunction<M, SSA>>,
    mut def: LowLevelILInstruction<'func, M, SSA>,
) -> Option<LowLevelILInstruction<'func, M, SSA>>
where
    M: FunctionMutability,
{
    while let Ok(copy) = CopyReg::try_from(def) {
        def = ssa.get_ssa_register_definition(&copy.source)?;
    }
    Some(def)
}

/// Result of matching the definition of a `RegPhi`'s incoming defs against instruction matchers of type `L` and `R`
/// Provides access to the matched instructions, as well as the `RegPhi`'s operands and the immediate
/// definitions of the operands before resolving any `SetRegSsa(_, RegSsa(..))` chains.
#[derive(Debug)]
pub struct PhiLoopSource<'func, M, L, R>
where
    M: FunctionMutability,
{
    /// The matched definition instructions after resolving `SetRegSsa(_, RegSsa(..))` chains
    pub matched: (L, R),
    /// The initial definition instruction for each phi operand before resolving any `SetRegSsa(_, RegSsa(..))` chains
    pub initial: (Instruction<'func, M, SSA>, Instruction<'func, M, SSA>),
    /// The SSA registers that were the oeprands of the `RegPhi` instruction
    pub source_regs: (
        LowLevelILSSARegisterKind<CoreRegister>,
        LowLevelILSSARegisterKind<CoreRegister>,
    ),
}

#[allow(unused)]
#[rustfmt::skip]
impl<'func, M, L, R> PhiLoopSource<'func, M, L, R>
where
    M: FunctionMutability,
{
    pub fn left(&self) -> (&L, &Instruction<'func, M, SSA>, LowLevelILSSARegisterKind<CoreRegister>) {
        (&self.matched.0, &self.initial.0, self.source_regs.0)
    }

    pub fn right(&self) -> (&R, &Instruction<'func, M, SSA>, LowLevelILSSARegisterKind<CoreRegister>) {
        (&self.matched.1, &self.initial.1, self.source_regs.1)
    }
}

/// Attempts to match the incoming defs of a `RegPhi` against instruction patterns T1 and T2.
/// This is used to match a register that is initialized before a loop and then modified
/// a single time within it, such as a loop counter.
pub fn match_phi_loop_sources<'func, M, T1, T2>(
    instr: &LowLevelILInstruction<'func, M, SSA>,
    ssa: &'func Ref<LowLevelILFunction<M, SSA>>,
) -> Option<PhiLoopSource<'func, M, T1, T2>>
where
    M: FunctionMutability,
    T1: TryFrom<LowLevelILInstruction<'func, M, SSA>>,
    T2: TryFrom<LowLevelILInstruction<'func, M, SSA>>,
{
    try_let_instr! {
        let RegPhi(_, sources) = instr else { return None }
    };

    if sources.len() != 2 {
        return None;
    }

    let initial_1 = ssa.get_ssa_register_definition(&sources[0])?;
    let initial_2 = ssa.get_ssa_register_definition(&sources[1])?;
    let resolved_1 = resolve_set_reg_ssa_to_reg_ssa_chain(ssa, initial_1)?;
    let resolved_2 = resolve_set_reg_ssa_to_reg_ssa_chain(ssa, initial_2)?;

    if let (Ok(t1), Ok(t2)) = (T1::try_from(resolved_1), T2::try_from(resolved_2)) {
        Some(PhiLoopSource {
            matched: (t1, t2),
            initial: (initial_1.into(), initial_2.into()),
            source_regs: (sources[0], sources[1]),
        })
    } else if let (Ok(t2), Ok(t1)) = (T1::try_from(resolved_2), T2::try_from(resolved_1)) {
        Some(PhiLoopSource {
            matched: (t2, t1),
            initial: (initial_2.into(), initial_1.into()),
            source_regs: (sources[1], sources[0]),
        })
    } else {
        None
    }
}
