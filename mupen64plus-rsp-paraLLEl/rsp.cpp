#include "rsp.hpp"
#include <utility>
#include <iostream>

using namespace std;

#define BREAKVAL 0xc07210e5e34d4157ull
static void breakme()
{
}

extern "C" {
#ifdef INTENSE_DEBUG
static uint64_t hash_imem(const uint8_t *data, size_t size)
{
   uint64_t h = 0xcbf29ce484222325ull;
   size_t i;
   for (i = 0; i < size; i++)
      h = (h * 0x100000001b3ull) ^ data[i];

   if (h == BREAKVAL)
      breakme();

   return h;
}

void RSP_DEBUG(RSP::CPUState *rsp, const char *tag, unsigned pc, unsigned value)
{
   uint64_t hash = hash_imem((const uint8_t*)rsp->cp2.regs, sizeof(rsp->cp2.regs));
   fprintf(stderr, "%s (PC: %u): %u, %llu\n", tag, pc, value, hash);
   if (value)
      fprintf(stderr, "  DMEM HASH: 0x%016llx\n", hash_imem((const uint8_t*)rsp->dmem, 0x1000));
}
#endif
}

namespace RSP
{
CPU::CPU()
{
   init_symbol_table();
}

CPU::~CPU()
{}

static const char *reg_names[32] = {
   "zero",
   "at",
   "v0",
   "v1",
   "a0",
   "a1",
   "a2",
   "a3",
   "t0",
   "t1",
   "t2",
   "t3",
   "t4",
   "t5",
   "t6",
   "t7",
   "s0",
   "s1",
   "s2",
   "s3",
   "s4",
   "s5",
   "s6",
   "s7",
   "t8",
   "t9",
   "k0",
   "k1",
   "gp",
   "sp",
   "s8",
   "ra",
};
#define NAME(reg) reg_names[reg]

void CPU::init_symbol_table()
{
#define S(sym) symbol_table["RSP_" #sym] = reinterpret_cast<uint64_t>(RSP_##sym)
   S(EXIT);
   S(CALL);
   S(RETURN);

#ifdef INTENSE_DEBUG
   S(DEBUG);
#endif
   S(MFC0);
   S(MTC0);

   S(MTC2);
   S(MFC2);
   S(CFC2);
   S(CTC2);

   S(LBV);
   S(LSV);
   S(LLV);
   S(LDV);
   S(LQV);
   S(LRV);
   S(LPV);
   S(LUV);
   S(LHV);
   S(LTV);

   S(SBV);
   S(SSV);
   S(SLV);
   S(SDV);
   S(SQV);
   S(SRV);
   S(SPV);
   S(SUV);
   S(SHV);
   S(SFV);
   S(STV);

   S(VMULF);
   S(VMULU);
   S(VMUDL);
   S(VMUDM);
   S(VMUDN);
   S(VMUDH);
   S(VMACF);
   S(VMACU);
   //S(VMACQ);
   S(VMADL);
   S(VMADM);
   S(VMADN);
   S(VMADH);
   S(VADD);
   S(VSUB);
   S(VABS);
   S(VADDC);
   S(VSUBC);
   S(VSAR);
   S(VLT);
   S(VEQ);
   S(VNE);
   S(VGE);
   S(VCL);
   S(VCH);
   S(VCR);
   S(VMRG);
   S(VAND);
   S(VNAND);
   S(VOR);
   S(VNOR);
   S(VXOR);
   S(VNXOR);
   S(VRCP);
   S(VRCPL);
   S(VRCPH);
   S(VMOV);
   S(VRSQ);
   S(VRSQL);
   S(VRSQH);
   S(VNOP);
#undef S
}

void CPU::invalidate_imem()
{
   for (unsigned i = 0; i < CODE_BLOCKS; i++)
      if (memcmp(cached_imem + i * CODE_BLOCK_WORDS, state.imem + i * CODE_BLOCK_WORDS, CODE_BLOCK_SIZE))
         state.dirty_blocks |= (0x3 << i) >> 1;
}

void CPU::invalidate_code()
{
   if (!state.dirty_blocks)
      return;

   for (unsigned i = 0; i < CODE_BLOCKS; i++)
   {
      if (state.dirty_blocks & (1 << i))
      {
         memset(blocks + i * CODE_BLOCK_WORDS, 0, CODE_BLOCK_WORDS * sizeof(blocks[0]));
         memcpy(cached_imem + i * CODE_BLOCK_WORDS, state.imem + i * CODE_BLOCK_WORDS, CODE_BLOCK_SIZE);
      }
   }

   state.dirty_blocks = 0;
}

// Need super-fast hash here.
uint64_t CPU::hash_imem(unsigned pc, unsigned count) const
{
   size_t size = count;

   // FNV-1.
   const auto *data = state.imem + pc;
   uint64_t h = 0xcbf29ce484222325ull;
   h = (h * 0x100000001b3ull) ^ pc;
   h = (h * 0x100000001b3ull) ^ count;
   for (size_t i = 0; i < size; i++)
      h = (h * 0x100000001b3ull) ^ data[i];
   return h;
}

unsigned CPU::analyze_static_end(unsigned pc, unsigned end)
{
   // Scans through IMEM and finds the logical "end" of the instruction stream.
   unsigned max_static_pc = pc;
   unsigned count = end - pc;

   for (unsigned i = 0; i < count; i++)
   {
      uint32_t instr = state.imem[pc + i];
      uint32_t type = instr >> 26;
      uint32_t target;

      bool forward_goto;
      if (pc + i + 1 >= max_static_pc)
      {
         forward_goto = false;
         max_static_pc = pc + i + 1;
      }
      else
         forward_goto = true;

      // VU
      if ((instr >> 25) == 0x25)
         continue;

      switch (type)
      {
         case 000:
            switch (instr & 63)
            {
               case 010:
                  // JR always terminates either by returning or exiting.
                  // We execute the next instruction via delay slot and exit.
                  // Unless we can branch past the JR
                  // (max_static_pc will be higher than expected),
                  // this will be the static end.
                  if (!forward_goto)
                  {
                     max_static_pc = max(pc + i + 2, max_static_pc);
                     goto end;
                  }
                  break;

               case 015:
                  // BREAK always terminates.
                  if (!forward_goto)
                     goto end;
                  break;

               default:
                  break;
            }
            break;

         case 001: // REGIMM
            switch ((instr >> 16) & 31)
            {
               case 000: // BLTZ
               case 001: // BGEZ
               case 021: // BGEZAL
               case 020: // BLTZAL
                  target = (pc + i + 1 + instr) & 0x3ff;
                  if (target >= pc && target < end) // goto
                     max_static_pc = max(max_static_pc, target + 1);
                  break;

               default:
                  break;
            }

         case 002:
            // J is resolved by goto.
            target = instr & 0x3ff;
            if (target >= pc && target < end) // goto
            {
               // J is a static jump, so if we aren't branching
               // past this instruction and we're branching backwards,
               // we can end the block here.
               if (!forward_goto && target < end)
               {
                  max_static_pc = max(pc + i + 2, max_static_pc);
                  goto end;
               }
               else
                  max_static_pc = max(max_static_pc, target + 1);
            }
            else if (!forward_goto)
            {
               // If we have static branch outside our block,
               // we terminate the block.
               max_static_pc = max(pc + i + 2, max_static_pc);
               goto end;
            }
            break;

         case 004: // BEQ
         case 005: // BNE
         case 006: // BLEZ
         case 007: // BGTZ
            target = (pc + i + 1 + instr) & 0x3ff;
            if (target >= pc && target < end) // goto
               max_static_pc = max(max_static_pc, target + 1);
            break;

         default:
            break;
      }
   }

end:
   unsigned ret = min(max_static_pc, end);
   return ret;
}

Func CPU::jit_region(uint64_t hash, unsigned pc, unsigned count)
{
   full_code.clear();
   body.clear();
   full_code.reserve(16 * 1024);
   body.reserve(16 * 1024);

   // Local branch delays resolve to within the block, so we can use goto.
   bool pending_local_branch_delay = false;
   bool pending_branch_delay = false;
   bool pending_call = false;
   bool pending_indirect_call = false;
   bool pending_return = false;

   bool pipe_pending_local_branch_delay = false;
   bool pipe_pending_branch_delay = false;
   bool pipe_pending_call = false;
   bool pipe_pending_indirect_call = false;
   bool pipe_pending_return = false;

   uint32_t branch_delay = 0;
   uint32_t pipe_branch_delay = 0;
   char buf[256];
#define APPEND(...) do { \
   sprintf(buf, __VA_ARGS__); body += buf; \
} while(0)
#define APPEND_RD_NOT_R0(...) if (rd != 0) do { \
   APPEND(__VA_ARGS__); \
} while(0)
#define APPEND_RT_NOT_R0(...) if (rt != 0) do { \
   APPEND(__VA_ARGS__); \
} while(0)

#define DISASM(...) do { \
   APPEND("// "); \
   APPEND(__VA_ARGS__); \
} while(0)

#define PIPELINE_BRANCH() do { \
   pending_local_branch_delay = pipe_pending_local_branch_delay; \
   pending_branch_delay = pipe_pending_branch_delay; \
   pending_call = pipe_pending_call; \
   pending_indirect_call = pipe_pending_indirect_call; \
   pending_return = pipe_pending_return; \
   branch_delay = pipe_branch_delay; \
   pipe_pending_local_branch_delay = false; \
   pipe_pending_branch_delay = false; \
   pipe_pending_call = false; \
   pipe_pending_indirect_call = false; \
   pipe_pending_return = false; \
   pipe_branch_delay = 0; \
   APPEND("ADVANCE_DELAY_SLOT();\n"); \
} while(0)

#define PROMOTE_LOCAL_DELAY_SLOT() do { \
   APPEND("if (pipe_branch) {\n"); \
   APPEND("  STATE->has_delay_slot = 1;\n"); \
   APPEND("  STATE->branch_target = %u;\n", pipe_branch_delay * 4); \
   APPEND("}\n"); \
} while(0)

#define PROMOTE_DELAY_SLOT() do { \
   if (pipe_pending_local_branch_delay) \
      PROMOTE_LOCAL_DELAY_SLOT(); \
   else if (pipe_pending_branch_delay) { \
      APPEND("  PROMOTE_DELAY_SLOT();\n"); \
   } \
} while(0)

   // Statically checks if we need to handle branch delay slots.
   // Only relevant if the last instruction did anything branch related.
   // Double branch delays are technically undefined, but I assume it works like this.
#define CHECK_BRANCH_DELAY() do { \
   if (pending_call && !pipe_pending_local_branch_delay && !pipe_pending_branch_delay) { \
      APPEND("if (LIKELY(branch)) {\n"); \
      APPEND("  RSP_CALL(opaque, 0x%03x, 0x%03x);\n", \
            branch_delay * 4, ((pc + i + 1) << 2) & (IMEM_SIZE - 1)); \
      APPEND("}\n"); \
   } else if (pending_indirect_call && !pipe_pending_local_branch_delay && !pipe_pending_branch_delay) { \
      APPEND("if (LIKELY(branch)) {\n"); \
      APPEND("  RSP_CALL(opaque, (branch_delay << 2) & %u, 0x%03x);\n", \
            IMEM_SIZE - 1, ((pc + i + 1) << 2) & (IMEM_SIZE - 1)); \
      APPEND("}\n"); \
   } else if (pending_return && !pipe_pending_local_branch_delay && !pipe_pending_branch_delay) { \
      APPEND("if (LIKELY(branch)) {\n"); \
      APPEND("  if (RSP_RETURN(opaque, (branch_delay << 2) & %u)) return;\n", IMEM_SIZE - 1); \
      APPEND("  STATE->pc = (branch_delay << 2) & %u;\n", IMEM_SIZE - 1); \
      APPEND("  EXIT(MODE_CONTINUE);\n"); \
      APPEND("}\n"); \
   } else if (pending_local_branch_delay) { \
      if (pipe_pending_local_branch_delay || pipe_pending_branch_delay) { \
         APPEND("if (branch && pipe_branch) {\n"); \
         APPEND("  STATE->pc = %u;\n", branch_delay * 4); \
         APPEND("  PROMOTE_DELAY_SLOT();\n"); \
         APPEND("  EXIT(MODE_CONTINUE);\n"); \
         APPEND("} else if (branch) {\n"); \
         APPEND("  goto pc_%03x;\n", branch_delay * 4); \
         APPEND("}\n"); \
      } else { \
         APPEND("if (branch) goto pc_%03x;\n", branch_delay * 4); \
      } \
   } else if (pending_branch_delay) { \
      APPEND("if (branch) {\n"); \
      APPEND("  STATE->pc = (branch_delay << 2) & %u;\n", IMEM_SIZE - 1); \
      PROMOTE_DELAY_SLOT(); \
      APPEND("  EXIT(MODE_CONTINUE);\n"); \
      APPEND("}\n"); \
   } \
   pending_call = false; \
   pending_indirect_call = false; \
   pending_return = false; \
   pending_branch_delay = false; \
   pending_local_branch_delay = false; \
} while(0)

#define CHECK_INHERIT_BRANCH_DELAY() do { \
   APPEND("if (UNLIKELY(STATE->has_delay_slot)) {\n"); \
   APPEND("  STATE->pc = STATE->branch_target;\n"); \
   APPEND("  STATE->has_delay_slot = 0;\n"); \
   PROMOTE_DELAY_SLOT(); \
   APPEND("  EXIT(MODE_CONTINUE);\n"); \
   APPEND("}\n"); \
} while(0)

#define EXIT_WITH_DELAY(mode) do { \
   if (pending_local_branch_delay) \
   { \
      APPEND("STATE->pc = branch ? %u : %u;\n", \
            branch_delay * 4, ((pc + i + 1) << 2) & (IMEM_SIZE - 1)); \
      APPEND("EXIT(%s);\n", #mode); \
   } \
   else if (pending_branch_delay) \
   { \
      APPEND("STATE->pc = branch ? ((branch_delay << 2) & %u) : %u;\n", \
            IMEM_SIZE - 1, ((pc + i + 1) << 2) & (IMEM_SIZE - 1)); \
      APPEND("EXIT(%s);\n", #mode); \
   } \
   else \
   { \
      APPEND("if (UNLIKELY(STATE->has_delay_slot)) {\n"); \
      APPEND("  STATE->pc = STATE->branch_target;\n"); \
      APPEND("  STATE->has_delay_slot = 0;\n"); \
      APPEND("  EXIT(%s);\n", #mode); \
      APPEND("} else {\n"); \
      APPEND("  STATE->pc = %u;\n", ((pc + i + 1) << 2) & (IMEM_SIZE - 1)); \
      APPEND("  EXIT(%s);\n", #mode); \
      APPEND("}\n"); \
   } \
} while(0)

   auto set_pc = [&](uint32_t next_pc) {
      next_pc &= (IMEM_SIZE >> 2) - 1;
      if (next_pc >= pc && next_pc < (pc + count))
      {
         pipe_pending_local_branch_delay = true;
         pipe_branch_delay = next_pc;
      }
      else
      {
         pipe_pending_branch_delay = true;
         pipe_branch_delay = next_pc;
         APPEND("pipe_branch_delay = %u;\n", next_pc);
      }
   };

   auto set_pc_indirect = [&](uint32_t reg) {
      pipe_pending_branch_delay = true;
      APPEND("BRANCH_INDIRECT((r%u & 0xfff) >> 2);\n", reg);
   };

   APPEND("unsigned branch = 0;\n");
   APPEND("unsigned branch_delay = 0;\n");
   APPEND("unsigned pipe_branch = 0;\n");
   APPEND("unsigned pipe_branch_delay = 0;\n");
   APPEND("unsigned cp0_result;\n");
   APPEND("unsigned addr;\n");
   APPEND("unsigned *dmem = STATE->dmem;\n");
   for (unsigned i = 0; i < count; i++)
   {
      APPEND("pc_%03x:\n", (pc + i) * 4);
      PIPELINE_BRANCH();

      uint32_t instr = state.imem[pc + i];
      uint32_t type = instr >> 26;
      uint32_t rd, rs, rt, shift, imm;
      int16_t simm;

      if ((instr >> 25) == 0x25)
      {
         // VU instruction.
         uint32_t op = instr & 63;
         uint32_t vd = (instr >> 6) & 31;
         uint32_t vs = (instr >> 11) & 31;
         uint32_t vt = (instr >> 16) & 31;
         uint32_t e  = (instr >> 21) & 15;

         static const char *ops[64] = {
            "VMULF", "VMULU", nullptr, nullptr, "VMUDL", "VMUDM", "VMUDN", "VMUDH",
            "VMACF", "VMACU", nullptr, nullptr, "VMADL", "VMADM", "VMADN", "VMADH",
            "VADD", "VSUB", nullptr, "VABS", "VADDC", "VSUBC", nullptr, nullptr,
            nullptr, nullptr, nullptr, nullptr, nullptr, "VSAR", nullptr, nullptr,
            "VLT", "VEQ", "VNE", "VGE", "VCL", "VCH", "VCR", "VMRG",
            "VAND", "VNAND", "VOR", "VNOR", "VXOR", "VNXOR", nullptr, nullptr,
            "VRCP", "VRCPL", "VRCPH", "VMOV", "VRSQ", "VRSQL", "VRSQH", "VNOP",
            nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
         };
         auto vop = ops[op];
         if (vop)
         {
            APPEND("RSP_%s(STATE, %u, %u, %u, %u);\n",
                  vop, vd, vs, vt, e);
            DISASM("%s v%u, v%u, v%u[%u]\n", vop, vd, vs, vt, e);
         }
         else
         {
            APPEND("RSP_RESERVED(STATE, %u, %u, %u, %u);\n",
                  vd, vs, vt, e);
            DISASM("RSP_RESERVED v%u, v%u, v%u[%u]\n", vd, vs, vt, e);
            //fprintf(stderr, "Unimplemented COP2 op %u.\n", op);
         }

#ifdef INTENSE_DEBUG
         APPEND("RSP_DEBUG(STATE, \"CP2\", %u, 0);\n", op);
#endif
      }
      else
      {
         // Everything else.
         switch (type)
         {
            case 000:
               {
                  rd = (instr & 0xffff) >> 11;
                  rt = (instr >> 16) & 31;
                  shift = (instr >> 6) & 31;
                  rs = instr >> 21;

                  switch (instr & 63)
                  {
                     case 000: // SLL
                        APPEND_RD_NOT_R0("r%u = r%u << %u;\n", rd, rt, shift);

                        if (instr)
                           DISASM("sll %s, %s, %u\n", NAME(rd), NAME(rt), shift);
                        else
                           DISASM("nop\n");
                        break;

                     case 002: // SRL
                        APPEND_RD_NOT_R0("r%u = r%u >> %u;\n", rd, rt, shift);
                        DISASM("srl %s, %s, %u\n", NAME(rd), NAME(rt), shift);
                        break;

                     case 003: // SRA
                        APPEND_RD_NOT_R0("r%u = (int)r%u >> (int)%u;\n", rd, rt, shift);
                        DISASM("sra %s, %s, %u\n", NAME(rd), NAME(rt), shift);
                        break;

                     case 004: // SLLV
                        APPEND_RD_NOT_R0("r%u = r%u << MASK_SA(r%u);\n", rd, rt, rs);
                        DISASM("sllv %s, %s, $%u\n", NAME(rd), NAME(rt), rs);
                        break;

                     case 006: // SRLV
                        APPEND_RD_NOT_R0("r%u = r%u >> MASK_SA(r%u);\n", rd, rt, rs);
                        DISASM("srlv %s, %s, $%u\n", NAME(rd), NAME(rt), rs);
                        break;

                     case 007: // SRAV
                        APPEND_RD_NOT_R0("r%u = (int)r%u >> (int)MASK_SA(r%u);\n", rd, rt, rs);
                        DISASM("srav %s, %s, $%u\n", NAME(rd), NAME(rt), rs);
                        break;

                     case 011: // JALR
                        if (rd != 0)
                        {
                           APPEND("r%u = %u;\n", rd, ((pc + i + 2) << 2) & 0xffc);
                        }
                        set_pc_indirect(rs);
                        pipe_pending_indirect_call = true;
                        DISASM("jalr %s\n", NAME(rs));
#ifdef INTENSE_DEBUG
                        APPEND("RSP_DEBUG(STATE, \"JALR\", pipe_branch_delay * 4, 0);\n");
#endif
                        break;
                     case 010: // JR
                        set_pc_indirect(rs);
                        pipe_pending_return = true;
                        DISASM("jr %s\n", NAME(rs));
#ifdef INTENSE_DEBUG
                        APPEND("RSP_DEBUG(STATE, \"JR\", pipe_branch_delay * 4, 0);\n");
#endif
                        break;

                     case 015: // BREAK
                        EXIT_WITH_DELAY(MODE_BREAK);
                        break;

                     case 040: // ADD
                     case 041: // ADDU
                        APPEND_RD_NOT_R0("r%u = r%u + r%u;\n", rd, rs, rt);
                        DISASM("add %s, %s, %s\n", NAME(rd), NAME(rs), NAME(rt));
                        break;

                     case 042: // SUB
                     case 043: // SUBU
                        APPEND_RD_NOT_R0("r%u = r%u - r%u;\n", rd, rs, rt);
                        DISASM("sub %s, %s, %s\n", NAME(rd), NAME(rs), NAME(rt));
                        break;

                     case 044: // AND
                        APPEND_RD_NOT_R0("r%u = r%u & r%u;\n", rd, rs, rt);
                        DISASM("and %s, %s, %s\n", NAME(rd), NAME(rs), NAME(rt));
                        break;

                     case 045: // OR
                        APPEND_RD_NOT_R0("r%u = r%u | r%u;\n", rd, rs, rt);
                        DISASM("or %s, %s, %s\n", NAME(rd), NAME(rs), NAME(rt));
                        break;

                     case 046: // XOR
                        APPEND_RD_NOT_R0("r%u = r%u ^ r%u;\n", rd, rs, rt);
                        DISASM("xor %s, %s, %s\n", NAME(rd), NAME(rs), NAME(rt));
                        break;

                     case 047: // NOR
                        APPEND_RD_NOT_R0("r%u = ~(r%u | r%u);\n", rd, rs, rt);
                        DISASM("nor %s, %s, %s\n", NAME(rd), NAME(rs), NAME(rt));
                        break;

                     case 052: // SLT
                        APPEND_RD_NOT_R0("r%u = (int)r%u < (int)r%u;\n", rd, rs, rt);
                        DISASM("slt %s, %s, %s\n", NAME(rd), NAME(rs), NAME(rt));
                        break;

                     case 053: // SLTU
                        APPEND_RD_NOT_R0("r%u = r%u < r%u;\n", rd, rs, rt);
                        DISASM("sltu %s, %s, %s\n", NAME(rd), NAME(rs), NAME(rt));
                        break;

                     default:
                        break;
                  }
                  break;
               }

            case 001: // REGIMM
               rs = (instr >> 21) & 31;
               rt = (instr >> 16) & 31;
               switch (rt)
               {
                  case 020: // BLTZAL
                     APPEND("r31 = %u;\n", ((pc + i + 2) << 2) & 0xffc);
                     rs = (instr >> 21) & 31;
                     set_pc(pc + i + 1 + instr);
                     APPEND("BRANCH_IF((int)r%u < 0);\n", rs);
                     DISASM("bltzal %s, 0x%x\n", NAME(rs), ((pc + i + 1 + instr) << 2) & 0xffc);
                     break;

                  case 000: // BLTZ
                     rs = (instr >> 21) & 31;
                     set_pc(pc + i + 1 + instr);
                     APPEND("BRANCH_IF((int)r%u < 0);\n", rs);
                     DISASM("bltz %s, 0x%x\n", NAME(rs), ((pc + i + 1 + instr) << 2) & 0xffc);
                     break;

                  case 021: // BGEZAL
                     APPEND("r31 = %u;\n", ((pc + i + 2) << 2) & 0xffc);
                     rs = (instr >> 21) & 31;
                     set_pc(pc + i + 1 + instr);
                     APPEND("BRANCH_IF((int)r%u >= 0);\n", rs);
                     DISASM("bgezal %s, 0x%x\n", NAME(rs), ((pc + i + 1 + instr) << 2) & 0xffc);
                     break;

                  case 001: // BGEZ
                     rs = (instr >> 21) & 31;
                     set_pc(pc + i + 1 + instr);
                     APPEND("BRANCH_IF((int)r%u >= 0);\n", rs);
                     DISASM("bgez %s, 0x%x\n", NAME(rs), ((pc + i + 1 + instr) << 2) & 0xffc);
                     break;

                  default:
                     break;
               }
               break;

            case 003: // JAL
               APPEND("r31 = %u;\n", ((pc + i + 2) << 2) & 0xffc);
               imm = instr & 0x3ff;
               set_pc(imm);
               pipe_pending_call = true;
               APPEND("BRANCH();\n");
               DISASM("jal 0x%x\n", (instr & 0x3ff) << 2);
#ifdef INTENSE_DEBUG
               APPEND("RSP_DEBUG(STATE, \"JAL\", %u, 0);\n", pipe_branch_delay * 4);
#endif
               break;

            case 002: // J
               imm = instr & 0x3ff;
               set_pc(imm);
               APPEND("BRANCH();\n");
               DISASM("j 0x%x\n", (instr & 0x3ff) << 2);
               break;

            case 004: // BEQ
               rs = (instr >> 21) & 31;
               rt = (instr >> 16) & 31;
               set_pc(pc + i + 1 + instr);
               APPEND("BRANCH_IF(r%u == r%u);\n", rs, rt);
               DISASM("beq %s, %s, 0x%x\n", NAME(rs), NAME(rt), ((pc + i + 1 + instr) & 0x3ff) << 2);
               break;

            case 005: // BNE
               rs = (instr >> 21) & 31;
               rt = (instr >> 16) & 31;
               set_pc(pc + i + 1 + instr);
               APPEND("BRANCH_IF(r%u != r%u);\n", rs, rt);
               DISASM("bne %s, %s, 0x%x\n", NAME(rs), NAME(rt), ((pc + i + 1 + instr) & 0x3ff) << 2);
               break;

            case 006: // BLEZ
               rs = (instr >> 21) & 31;
               set_pc(pc + i + 1 + instr);
               APPEND("BRANCH_IF((int)r%u <= 0);\n", rs);
               DISASM("blez %s, 0x%x\n", NAME(rs), ((pc + i + 1 + instr) & 0x3ff) << 2);
               break;

            case 007: // BGTZ
               rs = (instr >> 21) & 31;
               set_pc(pc + i + 1 + instr);
               APPEND("BRANCH_IF((int)r%u > 0);\n", rs);
               DISASM("bgtz %s, 0x%x\n", NAME(rs), ((pc + i + 1 + instr) & 0x3ff) << 2);
               break;

            case 010:
            case 011: // ADDI
               simm = instr;
               rs = (instr >> 21) & 31;
               rt = (instr >> 16) & 31;
               APPEND_RT_NOT_R0("r%u = (int)r%u + %d;\n", rt, rs, simm);

               if (rs != 0)
                  DISASM("addi %s, %s, %d\n", NAME(rt), NAME(rs), simm);
               else
                  DISASM("li %s, %d\n", NAME(rt), simm);
               break;

            case 012: // SLTI
               simm = instr;
               rs = (instr >> 21) & 31;
               rt = (instr >> 16) & 31;
               APPEND_RT_NOT_R0("r%u = (int)r%u < %d;\n", rt, rs, simm);
               DISASM("slti %s, %s, %d\n", NAME(rt), NAME(rs), simm);
               break;

            case 013: // SLTIU
               imm = instr & 0xffff;
               rs = (instr >> 21) & 31;
               rt = (instr >> 16) & 31;
               APPEND_RT_NOT_R0("r%u = r%u < %u;\n", rt, rs, imm);
               DISASM("sltiu %s, %s, %u\n", NAME(rt), NAME(rs), imm);
               break;

            case 014: // ANDI
               imm = instr & 0xffff;
               rs = (instr >> 21) & 31;
               rt = (instr >> 16) & 31;
               APPEND_RT_NOT_R0("r%u = r%u & %u;\n", rt, rs, imm);
               DISASM("andi %s, %s, 0x%x\n", NAME(rt), NAME(rs), imm);
               break;

            case 015: // ORI
               imm = instr & 0xffff;
               rs = (instr >> 21) & 31;
               rt = (instr >> 16) & 31;
               APPEND_RT_NOT_R0("r%u = r%u | %u;\n", rt, rs, imm);
               DISASM("ori %s, %s, 0x%x\n", NAME(rt), NAME(rs), imm);
               break;

            case 016: // XORI
               imm = instr & 0xffff;
               rs = (instr >> 21) & 31;
               rt = (instr >> 16) & 31;
               APPEND_RT_NOT_R0("r%u = r%u ^ %u;\n", rt, rs, imm);
               DISASM("xori %s, %s, 0x%x\n", NAME(rt), NAME(rs), imm);
               break;

            case 017: // LUI
               imm = instr & 0xffff;
               rt = (instr >> 16) & 31;
               APPEND_RT_NOT_R0("r%u = %uu << 16u;\n", rt, imm);
               DISASM("lui %s, 0x%x\n", NAME(rt), imm);
               break;

            case 020: // COP0
               rd = (instr >> 11) & 31;
               rs = (instr >> 21) & 31;
               rt = (instr >> 16) & 31;
               switch (rs)
               {
                  case 000: // MFC0
                     //APPEND("cp0_result = RSP_MFC0(STATE, %u, %u);\n", rt, rd);
                     if (rt)
                     {
                     APPEND("{unsigned res = *STATE->cp0.cr[%u & 15];\n",rd);
                     APPEND("STATE->sr[%u] = res;\n",rt);
                     APPEND("cp0_result = MODE_CONTINUE;}\n");
                     }
                     DISASM("mfc0 %u, %u\n", rt, rd);

                     APPEND("if (UNLIKELY(cp0_result != MODE_CONTINUE)) {\n");
                     EXIT_WITH_DELAY(cp0_result);
                     APPEND("}\n");
                     break;

                  case 004: // MTC0
                     //APPEND("cp0_result = RSP_MTC0(STATE, %u, %u);\n", rd, rt);
                   switch (static_cast<CP0Registers>(rd & 15))
                   {
                      case CP0_REGISTER_DMA_CACHE:
                         APPEND("{unsigned val = STATE->sr[%u];\n",rt);
                         APPEND("*STATE->cp0.cr[%u] = val & 0x1fff;\n",CP0_REGISTER_DMA_CACHE);
                         APPEND("cp0_result = MODE_CONTINUE;}\n");
                         break;

                      case CP0_REGISTER_DMA_DRAM:
                         APPEND("{unsigned val = STATE->sr[%u];\n",rt);
                         APPEND("*STATE->cp0.cr[%u] = val & 0xffffff;\n",CP0_REGISTER_DMA_DRAM);
                         APPEND("cp0_result = MODE_CONTINUE;}\n");
                         break;

                      case CP0_REGISTER_DMA_READ_LENGTH:
                         APPEND("cp0_result = RSP_MTC0(STATE, %u, %u);\n", rd, rt);
                         break;

                      case CP0_REGISTER_DMA_WRITE_LENGTH:
                         APPEND("cp0_result = RSP_MTC0(STATE, %u, %u);\n", rd, rt);
                         break;

                      case CP0_REGISTER_SP_STATUS:
                         APPEND("cp0_result = RSP_MTC0(STATE, %u, %u);\n", rd, rt);
                         break;

                      case CP0_REGISTER_SP_RESERVED:
                         // CXD4 forces this to 0.
                         APPEND("{*STATE->cp0.cr[%u] = 0;\n",CP0_REGISTER_SP_RESERVED);
                         APPEND("cp0_result = MODE_CONTINUE;}\n");
                         break;

                      case CP0_REGISTER_CMD_START:
                         APPEND("{unsigned val = STATE->sr[%u];\n",rt);
                         APPEND("*STATE->cp0.cr[%u] =\n",CP0_REGISTER_CMD_START);
                         APPEND("*STATE->cp0.cr[%u] =\n",CP0_REGISTER_CMD_CURRENT);
                         APPEND("*STATE->cp0.cr[%u] =\n",CP0_REGISTER_CMD_END);
                         APPEND("val & 0xfffffff8u;\n");
                         APPEND("cp0_result = MODE_CONTINUE;}\n");
                         break;

                      case CP0_REGISTER_CMD_END:
                         APPEND("cp0_result = RSP_MTC0(STATE, %u, %u);\n", rd, rt);
                         break;

                      case CP0_REGISTER_CMD_CLOCK:
                         APPEND("{unsigned val = STATE->sr[%u];\n",rt);
                         APPEND("*STATE->cp0.cr[%u] = val;\n",CP0_REGISTER_CMD_CLOCK);
                         APPEND("cp0_result = MODE_CONTINUE;}\n");
                         break;

                      case CP0_REGISTER_CMD_STATUS:
                         APPEND("{unsigned val = STATE->sr[%u];\n",rt);
                         APPEND("*STATE->cp0.cr[%u]    &= ~(!!(val &  0x1) << 0);\n",CP0_REGISTER_CMD_STATUS);
                         APPEND("*STATE->cp0.cr[%u]    |=  (!!(val &  0x2) << 0);\n",CP0_REGISTER_CMD_STATUS);
                         APPEND("*STATE->cp0.cr[%u]    &= ~(!!(val &  0x4) << 1);\n",CP0_REGISTER_CMD_STATUS);
                         APPEND("*STATE->cp0.cr[%u]    |=  (!!(val &  0x8) << 1);\n",CP0_REGISTER_CMD_STATUS);
                         APPEND("*STATE->cp0.cr[%u]    &= ~(!!(val & 0x10) << 2);\n",CP0_REGISTER_CMD_STATUS);
                         APPEND("*STATE->cp0.cr[%u]    |=  (!!(val & 0x20) << 2);\n",CP0_REGISTER_CMD_STATUS);
                         APPEND("*STATE->cp0.cr[%u]    &= !(val & 0x40) * -1;\n",CP0_REGISTER_CMD_TMEM_BUSY);
                         APPEND("*STATE->cp0.cr[%u]    &= !(val & 0x200) * -1;\n",CP0_REGISTER_CMD_CLOCK);
                         APPEND("cp0_result = MODE_CONTINUE;}\n");
                         break;

                      case CP0_REGISTER_CMD_CURRENT:
                      case CP0_REGISTER_CMD_BUSY:
                      case CP0_REGISTER_CMD_PIPE_BUSY:
                      case CP0_REGISTER_CMD_TMEM_BUSY:
                         break;

                      default:
                         APPEND("{unsigned val = STATE->sr[%u];\n",rt);
                         APPEND("*STATE->cp0.cr[%u & 15] = val;\n",rd);
                         APPEND("cp0_result = MODE_CONTINUE;}\n");
                         break;
                   }
                     DISASM("mtc0 %u, %u\n", rd, rt);

                     APPEND("if (UNLIKELY(cp0_result != MODE_CONTINUE)) {\n");
                     EXIT_WITH_DELAY(cp0_result);
                     APPEND("}\n");
                     break;

                  default:
                     break;
               }
               break;

            case 022: // COP2
               rd = (instr >> 11) & 31;
               rs = (instr >> 21) & 31;
               rt = (instr >> 16) & 31;
               imm = (instr >> 7) & 15;
               switch (rs)
               {
                  case 000: // MFC2
                     //APPEND("RSP_MFC2(STATE, %u, %u, %u);\n", rt, rd, imm);
                     if (rt != 0){
                        APPEND("{const unsigned short *e = (unsigned short *)STATE->cp2.regs[%u].e;\n",rd);
                        APPEND("unsigned lo = %u >> 1;\n",imm);
                        if (imm & 1)
                        {
                        APPEND("unsigned hi = ((%u + 1) >> 1) & 7;\n",imm);
                        APPEND("unsigned short high = e[lo] << 8;\n");
                        APPEND("unsigned char low = e[hi] >> 8;\n");
                        APPEND("STATE->sr[%u] = ((short)(high | low));}\n",rt);
                        }
                        else
                        {
                        APPEND("STATE->sr[%u] = ((short)(e[lo]));}\n",rt);
                        }
                     }
                     DISASM("mfc2 %u, %u, %u\n", rt, rd, imm);
                     break;

                  case 002: // CFC2
                     APPEND("RSP_CFC2(STATE, %u, %u);\n", rt, rd);
                     DISASM("cfc2 %u, %u\n", rt, rd);
                     break;

                  case 004: // MTC2
                     //APPEND("RSP_MTC2(STATE, %u, %u, %u);\n", rt, rd, imm);
                     APPEND("{unsigned short *e = (unsigned short *)STATE->cp2.regs[%u].e;\n",rd);
                     APPEND("unsigned lo = %u >> 1;\n",imm);
                     APPEND("unsigned rt = STATE->sr[%u];\n",rt);
                     if (imm & 1)
                     {
                     APPEND("unsigned hi = (%u + 1) >> 1;\n",imm);
                     APPEND("e[lo] = (e[lo] & 0xff00) | ((rt >> 8) & 0xff);\n");
                     APPEND("e[hi] = (e[lo] & 0x00ff) | ((rt & 0xff) << 8);}\n");
                     }
                     else
                     {
                     APPEND("e[lo] = rt;}\n");
                     }
                     DISASM("mtc2 %u, %u, %u\n", rt, rd, imm);
#ifdef INTENSE_DEBUG
                     APPEND("RSP_DEBUG(STATE, \"MTC2\", %u, 0);\n", 0);
#endif
                     break;

                  case 006: // CTC2
                     APPEND("RSP_CTC2(STATE, %u, %u);\n", rt, rd);
                     DISASM("mtc2 %u, %u\n", rt, rd);
                     break;

                  default:
                     break;
               }
               break;

            case 040: // LB
               simm = instr;
               rt = (instr >> 16) & 31;
               rs = (instr >> 21) & 31;
               if (rt != 0)
               {
                  APPEND("r%u = (signed char)READ_MEM_U8(dmem, (r%u + (%d)) & 0xfff);\n",
                        rt, rs, simm);
               }
               DISASM("lb %s, %d(%s)\n", NAME(rt), simm, NAME(rs));
               break;

            case 041: // LH
               simm = instr;
               rt = (instr >> 16) & 31;
               rs = (instr >> 21) & 31;
               if (rt != 0)
               {
                  APPEND("addr = (r%u + (%d)) & 0xfff;\n", rs, simm);
                  APPEND("if (UNLIKELY(addr & 1))\n");
                  APPEND("  r%u = (signed short)READ_MEM_U16_UNALIGNED(dmem, addr);\n", rt);
                  APPEND("else\n");
                  APPEND("  r%u = (signed short)READ_MEM_U16(dmem, addr);\n", rt);
               }
               DISASM("lh %s, %d(%s)\n", NAME(rt), simm, NAME(rs));
               break;

            case 043: // LW
               simm = instr;
               rt = (instr >> 16) & 31;
               rs = (instr >> 21) & 31;
               if (rt != 0)
               {
                  APPEND("addr = (r%u + (%d)) & 0xfff;\n", rs, simm);
                  APPEND("if (UNLIKELY(addr & 3))\n");
                  APPEND("  r%u = READ_MEM_U32_UNALIGNED(dmem, addr);\n", rt);
                  APPEND("else\n");
                  APPEND("  r%u = READ_MEM_U32(dmem, addr);\n", rt);
               }
               DISASM("lw %s, %d(%s)\n", NAME(rt), simm, NAME(rs));
               break;

            case 044: // LBU
               simm = instr;
               rt = (instr >> 16) & 31;
               rs = (instr >> 21) & 31;
               if (rt != 0)
               {
                  APPEND("r%u = READ_MEM_U8(dmem, (r%u + (%d)) & 0xfff);\n", rt, rs, simm);
               }
               DISASM("lbu %s, %d(%s)\n", NAME(rt), simm, NAME(rs));
               break;

            case 045: // LHU
               simm = instr;
               rt = (instr >> 16) & 31;
               rs = (instr >> 21) & 31;
               if (rt != 0)
               {

                  APPEND("addr = (r%u + (%d)) & 0xfff;\n", rs, simm);
                  APPEND("if (UNLIKELY(addr & 1))\n");
                  APPEND("  r%u = READ_MEM_U16_UNALIGNED(dmem, addr);\n", rt);
                  APPEND("else\n");
                  APPEND("  r%u = READ_MEM_U16(dmem, addr);\n", rt);
               }
               DISASM("lhu %s, %d(%s)\n", NAME(rt), simm, NAME(rs));
               break;

            case 050: // SB
               simm = instr;
               rt = (instr >> 16) & 31;
               rs = (instr >> 21) & 31;
               APPEND("WRITE_MEM_U8(dmem, ((r%u + (%d)) & 0xfff), r%u);\n", rs, simm, rt);
               DISASM("sb %s, %d(%s)\n", NAME(rt), simm, NAME(rs));
               break;

            case 051: // SH
               rt = (instr >> 16) & 31;
               rs = (instr >> 21) & 31;
               simm = instr;
               APPEND("addr = (r%u + (%d)) & 0xfff;\n", rs, simm);
               APPEND("if (UNLIKELY(addr & 1))\n");
               APPEND("  WRITE_MEM_U16_UNALIGNED(dmem, addr, r%u);\n", rt);
               APPEND("else\n");
               APPEND("  WRITE_MEM_U16(dmem, addr, r%u);\n", rt);
               DISASM("sh %s, %d(%s)\n", NAME(rt), simm, NAME(rs));
               break;

            case 053: // SW
               rt = (instr >> 16) & 31;
               rs = (instr >> 21) & 31;
               simm = instr;
               APPEND("addr = (r%u + (%d)) & 0xfff;\n", rs, simm);
               APPEND("if (UNLIKELY(addr & 3))\n");
               APPEND("  WRITE_MEM_U32_UNALIGNED(dmem, addr, r%u);\n", rt);
               APPEND("else\n");
               APPEND("  WRITE_MEM_U32(dmem, addr, r%u);\n", rt);
               DISASM("sw %s, %d(%s)\n", NAME(rt), simm, NAME(rs));
               break;

            case 062: // LWC2
            {
               rt = (instr >> 16) & 31;
               simm = instr;
               // Sign extend.
               simm <<= 9;
               simm >>= 9;
               rs = (instr >> 21) & 31;
               rd = (instr >> 11) & 31;
               imm = (instr >> 7) & 15;
               switch(rd)
               {
                  case 0: //LBV
                     //void RSP_LBV(RSP::CPUState *rsp, unsigned rt, unsigned e, int offset, unsigned base)
                     //APPEND("RSP_LBV(STATE, %u, %u, %d, %u);\n", rt, imm, simm, rs);
                     APPEND("{unsigned _addr = (STATE->sr[%u] + %d * 1) & 0xfff;\n",rs,simm); 
                     APPEND("((unsigned char*)(STATE->cp2.regs[%u].e))[MES(%u)] = READ_MEM_U8(STATE->dmem, _addr);}\n",rt,imm); 
                     DISASM("LBV %u, %u, %d, %u\n", rt, imm, simm, rs);
                  break;
                  case 1: //LSV
                     //APPEND("RSP_LSV(STATE, %u, %u, %d, %u);\n", rt, imm, simm, rs);
                     if (!(imm & 1))
                     {
                     imm >>= 1;
                     APPEND("{unsigned _addr = (STATE->sr[%u] + %d * 2) & 0xfff;\n",rs,simm); 
                     APPEND("unsigned correction = _addr & 3;\n");
                     APPEND("if (correction != 3){\n");
                     APPEND("unsigned short result;\n");
                     APPEND("if (correction == 1)\n");
                     APPEND("result = (READ_MEM_U8(STATE->dmem, _addr + 0) << 8) | (READ_MEM_U8(STATE->dmem, _addr + 1) << 0);\n");
                     APPEND("else \n result = READ_MEM_U16(STATE->dmem, _addr);\n");
                     APPEND("STATE->cp2.regs[%u].e[%d] = result;}}\n",rt,imm);
                     }
                     DISASM("LSV %u, %u, %d, %u\n", rt, imm, simm, rs);
                  break;
                  case 2: //LLV
                     //APPEND("RSP_LLV(STATE, %u, %u, %d, %u);\n", rt, imm, simm, rs);
                     if (!(imm & 1))
                     {
                     imm >>= 1;
                     APPEND("{unsigned _addr = (STATE->sr[%u] + %d * 4) & 0xfff;\n",rs,simm); 
                     APPEND("if (!(_addr & 1)){\n");
                     APPEND("STATE->cp2.regs[%u].e[%u] = READ_MEM_U16(STATE->dmem, _addr);\n",rt,imm);
                     APPEND("STATE->cp2.regs[%u].e[(%u + 1) & 7] = READ_MEM_U16(STATE->dmem, (_addr + 2) & 0xfff);}}\n",rt,imm);
                     imm <<= 1;
                     }
                     DISASM("LLV %u, %u, %d, %u\n", rt, imm, simm, rs);
                  break;
                  case 3: //LDV
                     //APPEND("RSP_LDV(STATE, %u, %u, %d, %u);\n", rt, imm, simm, rs);
                     if (!(imm & 1))
                     {
                     APPEND("{unsigned _addr = (STATE->sr[%u] + %d * 8) & 0xfff;\n",rs,simm);
                     APPEND("short *reg = STATE->cp2.regs[%u].e;\n",rt);
                     imm >>= 1;
                     APPEND("if (_addr & 1){;\n");
                     APPEND("reg[%u + 0] = (READ_MEM_U8(STATE->dmem, _addr + 0) << 8) | READ_MEM_U8(STATE->dmem, _addr + 1);\n",imm);
                     APPEND("reg[%u + 1] = (READ_MEM_U8(STATE->dmem, _addr + 2) << 8) | READ_MEM_U8(STATE->dmem, _addr + 3);\n",imm);
                     APPEND("reg[%u + 2] = (READ_MEM_U8(STATE->dmem, _addr + 4) << 8) | READ_MEM_U8(STATE->dmem, _addr + 5);\n",imm);
                     APPEND("reg[%u + 3] = (READ_MEM_U8(STATE->dmem, addr + 6) << 8) | READ_MEM_U8(STATE->dmem, _addr + 7);\n",imm);
                     APPEND("}else{\n");
                     APPEND("reg[%u + 0] = READ_MEM_U16(STATE->dmem, _addr);\n",imm);
                     APPEND("reg[%u + 1] = READ_MEM_U16(STATE->dmem, (_addr + 2) & 0xfff);\n",imm);
                     APPEND("reg[%u + 2] = READ_MEM_U16(STATE->dmem, (_addr + 4) & 0xfff);\n",imm);
                     APPEND("reg[%u + 3] = READ_MEM_U16(STATE->dmem, (_addr + 6) & 0xfff);}}\n",imm);
                     imm <<= 1;
                     }
                     DISASM("LDV %u, %u, %d, %u\n", rt, imm, simm, rs);
                  break;
                  case 4: //LQV
                     //APPEND("RSP_LQV(STATE, %u, %u, %d, %u);\n", rt, imm, simm, rs);
                     if (!(imm & 1))
                     {
                     APPEND("{unsigned _addr = (STATE->sr[%u] + %d * 16) & 0xfff;\n",rs,simm);
                     APPEND("if (!(_addr & 1)){\n");
                     APPEND("unsigned b = (_addr & 0xf) >> 1;\n");
                     imm >>= 1;
                     APPEND("short *reg = STATE->cp2.regs[%u].e;unsigned e = %u;\n",rt,imm);
                     APPEND("for (unsigned i = b; i < 8; i++, e++, _addr += 2)\n");
                     APPEND("reg[e] = READ_MEM_U16(STATE->dmem, _addr & 0xfff);}}\n");
                     imm <<= 1;
                     }
                     DISASM("LQV %u, %u, %d, %u\n", rt, imm, simm, rs);
                  break;
                  case 5: //LRV
                     //APPEND("RSP_LRV(STATE, %u, %u, %d, %u);\n", rt, imm, simm, rs);
                     if (imm == 0)
                     {
                     APPEND("{unsigned _addr = (STATE->sr[%u] + %d * 16) & 0xfff;\n",rs,simm);
                     APPEND("if (!(_addr & 1)){\n");
                     APPEND("unsigned b = (_addr & 0xf) >> 1;_addr &= ~0xf;\n");
                     APPEND("short *reg = STATE->cp2.regs[%u].e;unsigned e = %u;\n",rt,imm);
                     APPEND("for (e = 8 - b; e < 8; e++, _addr += 2){\n");
                     APPEND("reg[e] = READ_MEM_U16(STATE->dmem, _addr & 0xfff);}}}\n");
                     }
                     DISASM("LRV %u, %u, %d, %u\n", rt, imm, simm, rs);
                  break;
                  case 6: //LPV
                     //APPEND("RSP_LPV(STATE, %u, %u, %d, %u);\n", rt, imm, simm, rs);
                     if (!(imm & 1))
                     {
                     APPEND("{unsigned _addr = (STATE->sr[%u] + %d * 8) & 0xfff;\n",rs,simm);
                     APPEND("short *reg = STATE->cp2.regs[%u].e;\n",rt);
                     APPEND("for (unsigned i = 0; i < 8; i++){\n");
                     APPEND("reg[i] = READ_MEM_U8(STATE->dmem, (_addr + i) & 0xfff) << 8;}}\n");
                     }
                     DISASM("LPV %u, %u, %d, %u\n", rt, imm, simm, rs);
                  break;
                  case 7: //LUV
                     //APPEND("RSP_LUV(STATE, %u, %u, %d, %u);\n", rt, imm, simm, rs);
                     APPEND("{unsigned _addr = (STATE->sr[%u] + %d * 8) & 0xfff;\n",rs,simm);
                     APPEND("short *reg = STATE->cp2.regs[%u].e;\n",rt);
                     if (imm != 0)
                     {
                      APPEND("unsigned e = %u;_addr += -e & 0xf;\n",imm);
                      APPEND("for (unsigned b = 0; b < 8; b++){\n");
                      APPEND("reg[b] = READ_MEM_U8(STATE->dmem, _addr) << 7;\n");
                      APPEND("--e; _addr -= e ? 0 : 16; ++_addr;}}\n");
                     }
                     else
                     {
                      APPEND("for (unsigned i = 0; i < 8; i++){\n");
                      APPEND("reg[i] = READ_MEM_U8(STATE->dmem, (_addr + i) & 0xfff) << 7;}}\n");
                     }
                     DISASM("LUV %u, %u, %d, %u\n", rt, imm, simm, rs);
                  break;
                  case 8: //LHV
                     //APPEND("RSP_LHV(STATE, %u, %u, %d, %u);\n", rt, imm, simm, rs);
                     if (imm == 0)
                     {
                     APPEND("{unsigned _addr = (STATE->sr[%u] + %d * 16) & 0xfff;\n",rt,simm);
                     APPEND("if (!(_addr & 0xe)){\n");
                     APPEND("short *reg = STATE->cp2.regs[%u].e;\n",rt);
                     APPEND("for (unsigned i = 0; i < 8; i++){\n");
                     APPEND("reg[i] = READ_MEM_U8(STATE->dmem, _addr + 2 * i) << 7;}}}\n");
                     }
                     DISASM("LHV %u, %u, %d, %u\n", rt, imm, simm, rs);
                  break;                 
                  case 11: //LTV
                     //APPEND("RSP_LTV(STATE, %u, %u, %d, %u);\n", rt, imm, simm, rs);
                     if (imm & 1) break;
                     if (rt & 7) break;
                     APPEND("{unsigned _addr = (STATE->sr[%u] + %d * 16) & 0xfff;\n",rt,simm);
                     APPEND("if (!(_addr & 0xf)){\n");
                     APPEND("for (unsigned i = 0; i < 8; i++)\n");
                     APPEND("STATE->cp2.regs[%u + i].e[(-%u / 2 + i) & 7] = READ_MEM_U16(STATE->dmem, _addr + 2 * i);}}\n",rt,imm);
                     DISASM("LTV %u, %u, %d, %u\n", rt, imm, simm, rs);
                  break;
                  default:
                       static const char *lwc2_ops[32] = {
                          "LBV", "LSV", "LLV", "LDV", "LQV", "LRV", "LPV", "LUV",
                          "LHV", nullptr, nullptr, "LTV", nullptr, nullptr, nullptr, nullptr,
                          nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                          nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                       };
                       auto *op = lwc2_ops[rd];
                       if (op)
                       {
                          APPEND("RSP_%s(STATE, %u, %u, %d, %u);\n", op, rt, imm, simm, rs);
                          DISASM("%s %u, %u, %d, %u\n", op, rt, imm, simm, rs);
                       }
                  break;
               }

#ifdef INTENSE_DEBUG
               APPEND("RSP_DEBUG(STATE, \"LWC2\", %u, %u);\n", (pc + i + 1) << 2, instr);
#endif
               break;
            }

            case 072: // SWC2
            {
               rt = (instr >> 16) & 31;
               simm = instr;
               // Sign extend.
               simm <<= 9;
               simm >>= 9;
               rs = (instr >> 21) & 31;
               rd = (instr >> 11) & 31;
               imm = (instr >> 7) & 15;
               switch(rd)
               {
                  case 0: //SBV
                     //void RSP_SBV(RSP::CPUState *rsp, unsigned rt, unsigned e, int offset, unsigned base)
                     //APPEND("RSP_SBV(STATE, %u, %u, %d, %u);\n", rt, imm, simm, rs);
                     APPEND("{unsigned _addr = (STATE->sr[%u] + %d * 1) & 0xfff;\n",rs,simm);  
                     APPEND("unsigned char v = ((unsigned char*)(STATE->cp2.regs[%u].e))[MES(%u)];\n",rt,imm);
                     APPEND("WRITE_MEM_U8(STATE->dmem, _addr, v);}\n");
                     DISASM("SBV %u, %u, %d, %u\n", rt, imm, simm, rs);
                  break;
                  
                  case 1: //SSV
                     //APPEND("RSP_SSV(STATE, %u, %u, %d, %u);\n", rt, imm, simm, rs);
		             APPEND("{unsigned _addr = (STATE->sr[%u] + (%d * 2)) & 0xfff;\n",rs,simm);
	                 APPEND("unsigned char v0 = ((unsigned char*)(STATE->cp2.regs[%u].e))[MES(%u)];\n",rt,imm);
		             APPEND("unsigned char v1 = ((unsigned char*)(STATE->cp2.regs[%u].e))[MES(((%u+1) & 0xf))];\n",rt,imm);
                     APPEND("WRITE_MEM_U8(STATE->dmem, _addr, v0);\n");
                     APPEND("WRITE_MEM_U8(STATE->dmem, (_addr + 1) & 0xfff, v1);}\n");
                     DISASM("SSV %u, %u, %d, %u\n", rt, imm, simm, rs);
                  break;

                  case 2: //SLV
                      //APPEND("RSP_SLV(STATE, %u, %u, %d, %u);\n", rt, imm, simm, rs);
                      if (!((imm & 1) || (imm > 0xc)))
                      {
                      APPEND("{unsigned _addr = (STATE->sr[%u] + %d * 4) & 0xfff;\n",rs,simm);
                      APPEND("if (!(_addr & 1)){ \n");
                      imm >>= 1;
		              APPEND("unsigned short v0 = STATE->cp2.regs[%u].e[%u];\n",rt,imm);
		              APPEND("unsigned short v1 = STATE->cp2.regs[%u].e[%u + 1];\n",rt,imm);
		              APPEND("WRITE_MEM_U16(STATE->dmem, _addr, v0);\n");
		              APPEND("WRITE_MEM_U16(STATE->dmem, (_addr + 2) & 0xfff, v1);}};\n");
                      imm <<= 1;
                      }
                      DISASM("SLV %u, %u, %d, %u\n", rt, imm, simm, rs);
                  break;

                  case 3: //SDV
                      //APPEND("RSP_SDV(STATE, %u, %u, %d, %u);\n", rt, imm, simm, rs);
                      APPEND("{unsigned _addr = (STATE->sr[%u] + %d * 8) & 0xfff;\n",rs,simm);
		              APPEND("if ((%u > 8) || (%u & 1) || (_addr & 1)){\n",imm,imm);
		              APPEND("for (unsigned i = 0; i < 8; i++){\n");
		              APPEND("WRITE_MEM_U8(STATE->dmem, (_addr + i) & 0xfff,\n");
		              APPEND("((unsigned char*)(STATE->cp2.regs[%u].e))[MES((%u + i) & 0xf)]);\n",rt,imm);
		              APPEND("}}else{\n");
		              imm >>= 1;
		              APPEND("for (unsigned i = 0; i < 4; i++){\n");
		              APPEND("WRITE_MEM_U16(STATE->dmem, (_addr + 2 * i) & 0xfff,STATE->cp2.regs[%u].e[%u + i]);\n",rt,imm);
		              APPEND("}}}\n");
                      DISASM("SDV %u, %u, %d, %u\n", rt, imm, simm, rs);
                  break;

                  case 4: //SQV
                      //APPEND("RSP_SQV(STATE, %u, %u, %d, %u);\n", rt, imm, simm, rs);
		              APPEND("{unsigned _addr = (STATE->sr[%u] + %d * 16) & 0xfff;\n",rs,simm);
		              APPEND("if (!(_addr & 1)){;\n");
		              APPEND("unsigned b = _addr & 0xf; short *reg = STATE->cp2.regs[%u].e;\n",rt);
		              APPEND("if (%u != 0){\n",imm);
		              APPEND("for (unsigned i = 0; i < 16 - b; i++, _addr++) {\n");
		              APPEND("WRITE_MEM_U8(STATE->dmem, _addr & 0xfff,\n");
		              APPEND("((unsigned char*)(reg))[MES((%u + i) & 0xf)]);\n",imm);
		              APPEND("}}else{ b >>= 1;unsigned e = %u;\n",imm);
		              APPEND("for (unsigned i = b; i < 8; i++, e++, _addr += 2)\n");
		              APPEND("WRITE_MEM_U16(STATE->dmem, _addr & 0xfff, reg[e]);\n");
		              APPEND("}}}\n");
                      DISASM("SQV %u, %u, %d, %u\n", rt, imm, simm, rs);
                  break;

                  case 5: //SRV
                      //APPEND("RSP_SRV(STATE, %u, %u, %d, %u);\n", rt, imm, simm, rs);
                      if (imm == 0)
                      {
                        APPEND("{unsigned _addr = (STATE->sr[%u] + %d * 16) & 0xfff;\n",rs,simm);
                        APPEND("if (!(_addr & 1))\n");
                        APPEND("unsigned b = (_addr & 0xf) >> 1;_addr &= ~0xf;\n");
                        APPEND("short *reg = STATE->cp2.regs[%u].e;unsigned e = %u;\n",rt,imm);
                        APPEND("for (e = 8 - b; e < 8; e++, _addr += 2){\n");
                        APPEND("WRITE_MEM_U16(STATE->dmem, _addr & 0xfff, reg[e]);}}\n");
                      }
                      DISASM("SRV %u, %u, %d, %u\n", rt, imm, simm, rs);
                  break;                  
                  case 6: //SPV
                      //APPEND("RSP_SPV(STATE, %u, %u, %d, %u);\n", rt, imm, simm, rs);
                      if (imm == 0)
                      {
                        APPEND("{unsigned _addr = (STATE->sr[%u] + %d * 8) & 0xfff;\n",rs,simm);
                        APPEND("short *reg = STATE->cp2.regs[%u].e;\n",rt);
                        APPEND("for (unsigned i = 0; i < 8; i++)\n");
                        APPEND("WRITE_MEM_U8(STATE->dmem, (_addr + i) & 0xfff, ((short)(reg[i])) >> 8);}\n");
                      }
                      DISASM("SPV %u, %u, %d, %u\n", rt, imm, simm, rs);
                  break;                  
                  case 7: //SUV
                      //APPEND("RSP_SUV(STATE, %u, %u, %d, %u);\n", rt, imm, simm, rs);
                      if (imm == 0)
                      {
                        APPEND("{unsigned _addr = (STATE->sr[%u] + %d * 8) & 0xfff;\n",rs,simm);
                        APPEND("short *reg = STATE->cp2.regs[%u].e;\n",rt);
                        APPEND("for (unsigned i = 0; i < 8; i++)\n");
                        APPEND("WRITE_MEM_U8(STATE->dmem, (_addr + i) & 0xfff, ((short)(reg[i])) >> 7);}\n");
                      }
                      DISASM("SUV %u, %u, %d, %u\n", rt, imm, simm, rs);
                  break;                  
                  case 8: //SHV
                      //APPEND("RSP_SHV(STATE, %u, %u, %d, %u);\n", rt, imm, simm, rs);
                      if (imm == 0)
                      {
                      APPEND("{unsigned _addr = (STATE->sr[%u] + %d * 16) & 0xfff;\n",rs,simm);
                      APPEND("short *reg = STATE->cp2.regs[%u].e;\n",rt);
                      APPEND("for (unsigned i = 0; i < 8; i++)\n");
                      APPEND("WRITE_MEM_U8(STATE->dmem, (_addr + 2 * i) & 0xfff, ((short)(reg[i])) >> 7);}\n");
                      }
                      DISASM("SHV %u, %u, %d, %u\n", rt, imm, simm, rs);
                  break;                 
                  case 9: //SFV
                       //APPEND("RSP_SFV(STATE, %u, %u, %d, %u);\n", rt, imm, simm, rs);
                       APPEND("{unsigned _addr = (STATE->sr[%u] + %d * 16) & 0xff3;\n",rs,simm);
                       APPEND("short *reg = STATE->cp2.regs[%u].e;\n",rt);
                       switch (imm)
                       {
                          case 0:
                             APPEND("WRITE_MEM_U8(STATE->dmem, (_addr +  0) & 0xfff, ((short)(reg[0])) >> 7);\n");
                             APPEND("WRITE_MEM_U8(STATE->dmem, (_addr +  4) & 0xfff, ((short)(reg[1])) >> 7);\n");
                             APPEND("WRITE_MEM_U8(STATE->dmem, (_addr +  8) & 0xfff, ((short)(reg[2])) >> 7);\n");
                             APPEND("WRITE_MEM_U8(STATE->dmem, (_addr + 12) & 0xfff, ((short)(reg[3])) >> 7);\n");
                             break;

                          case 8:
                             APPEND("WRITE_MEM_U8(STATE->dmem, (_addr +  0) & 0xfff, ((short)(reg[4])) >> 7);\n");
                             APPEND("WRITE_MEM_U8(STATE->dmem, (_addr +  4) & 0xfff, ((short)(reg[5])) >> 7);\n");
                             APPEND("WRITE_MEM_U8(STATE->dmem, (_addr +  8) & 0xfff, ((short)(reg[6])) >> 7);\n");
                             APPEND("WRITE_MEM_U8(STATE->dmem, (_addr + 12) & 0xfff, ((short)(reg[7])) >> 7);\n");
                             break;

                          default:
                             break;
                       }
                       DISASM("SFV %u, %u, %d, %u\n", rt, imm, simm, rs);
                  break;
                  case 11: //STV
                      //APPEND("RSP_STV(STATE, %u, %u, %d, %u);\n", rt, imm, simm, rs);
                      if (!((imm & 1)||(rt & 7)))
                      {
                        APPEND("{unsigned _addr = (STATE->sr[%u] + %d * 16) & 0xfff;\n",rs,simm);
                        APPEND("if (!(_addr & 0xf)){\n");
                        APPEND("for (unsigned i = 0; i < 8; i++){\n");
                        APPEND("WRITE_MEM_U16(STATE->dmem, _addr + 2 * i,\n");
                        APPEND("STATE->cp2.regs[%u + ((%u / 2 + i) & 7)].e[i]);}}}\n",rt,imm);
                      }
                      DISASM("STV %u, %u, %d, %u\n", rt, imm, simm, rs);
                  break; 
                  default:
                     static const char *swc2_ops[32] = {
                       "SBV", "SSV", "SLV", "SDV", "SQV", "SRV", "SPV", "SUV",
                       "SHV", "SFV", nullptr, "STV", nullptr, nullptr, nullptr, nullptr,
                       nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                       nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                     };
                     auto *op = swc2_ops[rd];
                     if (op)
                     {
                       APPEND("RSP_%s(STATE, %u, %u, %d, %u);\n", op, rt, imm, simm, rs);
                       DISASM("%s %u, %u, %d, %u\n", op, rt, imm, simm, rs);
                      }
                  break;

               }
#ifdef INTENSE_DEBUG
               APPEND("RSP_DEBUG(STATE, \"SWC2\", %u, %u);\n", (pc + i + 1) << 2, instr);
#endif

               break;
            }

            default:
               break;
         }
      }

      if (i == 0)
         CHECK_INHERIT_BRANCH_DELAY();
      else
         CHECK_BRANCH_DELAY();
      APPEND("\n");
   }

   // Falling off end of block.
   APPEND("STATE->pc = %u;\n",
         ((pc + count) << 2) & (IMEM_SIZE - 1));
   PROMOTE_DELAY_SLOT();
   APPEND("EXIT(MODE_CONTINUE);\n");

   // Emit helper code.
   full_code += R"DELIM(

struct AlignedRSPVector1
{
  short e[8];
}__attribute__((aligned(16)));

struct AlignedRSPVector2
{
  short e[8 * 2];
}__attribute__((aligned(16)));

struct AlignedRSPVector3
{
  short e[8 * 3];
}__attribute__((aligned(16)));

struct CP2
{
   struct AlignedRSPVector1 regs[32];
   struct AlignedRSPVector2 flags[3];
   struct AlignedRSPVector3 acc;
   short div_out;
   short div_in;
   char dp_flag;
}__attribute__((aligned(64)));

struct CP0
{
  unsigned *cr[16];
  unsigned *irq;
};

struct cpu_state
{
   unsigned pc;
   unsigned dirty_blocks;
   unsigned has_delay_slot;
   unsigned branch_target;
   unsigned sr[32];
   unsigned *dmem;
   unsigned *imem;
   unsigned *rdram;
   struct CP2 cp2;
   struct CP0 cp0;
};

#define UNLIKELY(x) __builtin_expect(!!x, 0)
#define LIKELY(x) __builtin_expect(!!x, 1)
#define MASK_SA(x) ((x) & 31)

enum ReturnMode {
   MODE_ENTER = 0,
   MODE_CONTINUE = 1,
   MODE_BREAK = 2,
   MODE_DMA_READ = 3,
   MODE_CHECK_FLAGS = 4
};
#define r0 0
#define ADVANCE_DELAY_SLOT() do { \
   branch = pipe_branch; \
   pipe_branch = 0; \
   branch_delay = pipe_branch_delay; \
} while(0)

#define BRANCH() pipe_branch = 1
#define BRANCH_IF(x) if (x) BRANCH()
#define BRANCH_INDIRECT(pc) do { \
   pipe_branch_delay = pc; \
   pipe_branch = 1; \
} while(0)

#define PROMOTE_DELAY_SLOT() do { \
   if (pipe_branch) { \
      STATE->has_delay_slot = 1; \
      STATE->branch_target = pipe_branch_delay * 4; \
   } \
} while(0)

extern int RSP_MFC0(struct cpu_state *STATE, unsigned rt, unsigned rd);
extern int RSP_MTC0(struct cpu_state *STATE, unsigned rd, unsigned rt);

extern void RSP_MTC2(struct cpu_state *STATE, unsigned rt, unsigned vd, unsigned e);
extern void RSP_MFC2(struct cpu_state *STATE, unsigned rt, unsigned vs, unsigned e);
extern void RSP_CFC2(struct cpu_state *STATE, unsigned rt, unsigned rd);
extern void RSP_CTC2(struct cpu_state *STATE, unsigned rt, unsigned rd);

#define DECL_LS(op) \
   extern void RSP_##op(struct cpu_state *STATE, unsigned rt, unsigned element, int offset, unsigned base)

DECL_LS(LBV);
DECL_LS(LSV);
DECL_LS(LLV);
DECL_LS(LDV);
DECL_LS(LQV);
DECL_LS(LRV);
DECL_LS(LPV);
DECL_LS(LUV);
DECL_LS(LHV);
DECL_LS(LTV);

DECL_LS(SBV);
DECL_LS(SSV);
DECL_LS(SLV);
DECL_LS(SDV);
DECL_LS(SQV);
DECL_LS(SRV);
DECL_LS(SPV);
DECL_LS(SUV);
DECL_LS(SHV);
DECL_LS(SFV);
DECL_LS(STV);

extern void RSP_CALL(void *opaque, unsigned target, unsigned ret);
extern int RSP_RETURN(void *opaque, unsigned pc);
extern void RSP_EXIT(void *opaque, enum ReturnMode mode);
#define EXIT(mode) RSP_EXIT(opaque, mode)

extern void RSP_DEBUG(struct cpu_state *STATE, const char *tag, unsigned pc, unsigned value);

#define DECL_COP2(op) \
   extern void RSP_##op(struct cpu_state *STATE, unsigned vd, unsigned vs, unsigned vt, unsigned e)
DECL_COP2(VMULF);
DECL_COP2(VMULU);
DECL_COP2(VMUDL);
DECL_COP2(VMUDM);
DECL_COP2(VMUDN);
DECL_COP2(VMUDH);
DECL_COP2(VMACF);
DECL_COP2(VMACU);
//DECL_COP2(VMACQ);
DECL_COP2(VMADL);
DECL_COP2(VMADM);
DECL_COP2(VMADN);
DECL_COP2(VMADH);
DECL_COP2(VADD);
DECL_COP2(VSUB);
DECL_COP2(VABS);
DECL_COP2(VADDC);
DECL_COP2(VSUBC);
DECL_COP2(VSAR);
DECL_COP2(VLT);
DECL_COP2(VEQ);
DECL_COP2(VNE);
DECL_COP2(VGE);
DECL_COP2(VCL);
DECL_COP2(VCH);
DECL_COP2(VCR);
DECL_COP2(VMRG);
DECL_COP2(VAND);
DECL_COP2(VNAND);
DECL_COP2(VOR);
DECL_COP2(VNOR);
DECL_COP2(VXOR);
DECL_COP2(VNXOR);
DECL_COP2(VRCP);
DECL_COP2(VRCPL);
DECL_COP2(VRCPH);
DECL_COP2(VMOV);
DECL_COP2(VRSQ);
DECL_COP2(VRSQL);
DECL_COP2(VRSQH);
DECL_COP2(VNOP);
DECL_COP2(RESERVED);

#define HES(x) ((x) ^ 2)
#define BES(x) ((x) ^ 3)
#define MES(x) ((x) ^ 1)

#define READ_MEM_U8(mem, addr) \
   (((const unsigned char*)(mem))[BES(addr)])
#define READ_MEM_U16(mem, addr) \
   (((const unsigned short*)(mem))[HES(addr) >> 1])
#define READ_MEM_U32(mem, addr) \
   (((const unsigned*)(mem))[addr >> 2])

#define READ_MEM_U16_UNALIGNED(mem, addr) \
   (READ_MEM_U8(mem, addr) << 8) | READ_MEM_U8(mem, (addr + 1) & 0xfff)

#define READ_MEM_U32_UNALIGNED(mem, addr) \
   (READ_MEM_U8(mem, addr) << 24) | (READ_MEM_U8(mem, (addr + 1) & 0xfff) << 16) | \
   (READ_MEM_U8(mem, (addr + 2) & 0xfff) << 8) | READ_MEM_U8(mem, (addr + 3) & 0xfff)

#define WRITE_MEM_U8(mem, addr, data) \
   (((unsigned char*)(mem))[BES(addr)] = data)

#define WRITE_MEM_U16_UNALIGNED(mem, addr, data) do { \
   WRITE_MEM_U8(mem, addr, data >> 8); \
   WRITE_MEM_U8(mem, (addr + 1) & 0xfff, data & 0xff); \
} while(0)

#define WRITE_MEM_U32_UNALIGNED(mem, addr, data) do { \
   WRITE_MEM_U8(mem, addr, data >> 24); \
   WRITE_MEM_U8(mem, (addr + 1) & 0xfff, (data >> 16) & 0xff); \
   WRITE_MEM_U8(mem, (addr + 2) & 0xfff, (data >> 8) & 0xff); \
   WRITE_MEM_U8(mem, (addr + 3) & 0xfff, data & 0xff); \
} while(0)

#define WRITE_MEM_U16(mem, addr, data) \
   (((unsigned short*)(mem))[HES(addr) >> 1] = data)
#define WRITE_MEM_U32(mem, addr, data) \
   (((unsigned*)(mem))[addr >> 2] = data)

)DELIM";
   full_code += "void block_entry(void *opaque, struct cpu_state *STATE)\n";
   full_code += "{\n";

   for (unsigned i = 1; i < 32; i++)
   {
      char buf[32];
      sprintf(buf, "#define r%u (STATE->sr[%u])\n", i, i);
      full_code += buf;
   }

   // Emit fixup code.

   full_code += body;
   full_code += "}\n";

   std::cout << full_code;

   unique_ptr<Block> block(new Block(symbol_table));
   if (!block->compile(hash, full_code))
      return nullptr;

   auto ret = block->get_func();
   cached_blocks[pc][hash] = move(block);
   return ret;
}

void CPU::print_registers()
{
   fprintf(stderr, "RSP state:\n");
   fprintf(stderr, "  PC: 0x%03x\n", state.pc);
   for (unsigned i = 1; i < 32; i++)
      fprintf(stderr, "  SR[%s] = 0x%08x\n", NAME(i), state.sr[i]);
   fprintf(stderr, "\n");
   for (unsigned i = 0; i < 32; i++)
   {
      fprintf(stderr, "  VR[%02u] = { 0x%04x, 0x%04x, 0x%04x, 0x%04x, 0x%04x, 0x%04x, 0x%04x, 0x%04x }\n",
            i,
            state.cp2.regs[i].e[0],
            state.cp2.regs[i].e[1],
            state.cp2.regs[i].e[2],
            state.cp2.regs[i].e[3],
            state.cp2.regs[i].e[4],
            state.cp2.regs[i].e[5],
            state.cp2.regs[i].e[6],
            state.cp2.regs[i].e[7]);
   }

   fprintf(stderr, "\n");

   for (unsigned i = 0; i < 3; i++)
   {
      static const char *strings[] = { "ACC_HI", "ACC_MD", "ACC_LO" };
      fprintf(stderr, "  %s = { 0x%04x, 0x%04x, 0x%04x, 0x%04x, 0x%04x, 0x%04x, 0x%04x, 0x%04x }\n",
            strings[i],
            state.cp2.acc.e[8 * i + 0],
            state.cp2.acc.e[8 * i + 1],
            state.cp2.acc.e[8 * i + 2],
            state.cp2.acc.e[8 * i + 3],
            state.cp2.acc.e[8 * i + 4],
            state.cp2.acc.e[8 * i + 5],
            state.cp2.acc.e[8 * i + 6],
            state.cp2.acc.e[8 * i + 7]);
   }

   fprintf(stderr, "\n");

   for (unsigned i = 0; i < 3; i++)
   {
      static const char *strings[] = { "VCO", "VCC", "VCE" };
      uint16_t flags = rsp_get_flags(state.cp2.flags[i].e);
      fprintf(stderr, "  %s = 0x%04x\n", strings[i], flags);
   }

   fprintf(stderr, "\n");
   fprintf(stderr, "  Div Out = 0x%04x\n", state.cp2.div_out);
   fprintf(stderr, "  Div In  = 0x%04x\n", state.cp2.div_in);
   fprintf(stderr, "  DP flag = 0x%04x\n", state.cp2.dp_flag);
}

void CPU::exit(ReturnMode mode)
{
#ifdef _WIN32
   longjmp(env, mode);
#else
   siglongjmp(env, mode);
#endif
}

void CPU::call(uint32_t target, uint32_t ret)
{
   if (call_stack_ptr < CALL_STACK_SIZE)
      call_stack[call_stack_ptr++] = ret;
   enter(target);
}

int CPU::ret(uint32_t pc)
{
   if (call_stack_ptr == 0)
      return 0;

   uint32_t ret = call_stack[--call_stack_ptr];
   return ret == pc;
}

extern "C" {
void RSP_CALL(void *cpu, unsigned target, unsigned ret)
{
   static_cast<CPU *>(cpu)->call(target, ret);
}

void RSP_RETURN(void *cpu, unsigned pc)
{
   static_cast<CPU *>(cpu)->ret(pc);
}

void RSP_EXIT(void *cpu, int mode)
{
   static_cast<CPU *>(cpu)->exit(static_cast<ReturnMode>(mode));
}
}

void CPU::enter(uint32_t pc)
{
   pc &= IMEM_SIZE - 1;
   uint32_t word_pc = pc >> 2;
   auto &block = blocks[word_pc];
   //static unsigned countex, countre, countcomp;
   if (!block)
   {
      unsigned end = (pc + (CODE_BLOCK_SIZE * 2)) >> CODE_BLOCK_SIZE_LOG2;
      end <<= CODE_BLOCK_SIZE_LOG2 - 2;
      end = min(end, unsigned(IMEM_SIZE >> 2));
      end = analyze_static_end(word_pc, end);

      uint64_t hash = hash_imem(word_pc, end - word_pc);
      auto itr = cached_blocks[word_pc].find(hash);
      if (itr != cached_blocks[word_pc].end())
      {
         block = itr->second->get_func();
         //fprintf(stdout, "jit reuse #%u comp: %u exec: %u \n", ++countre, countcomp, countex);
      }
      else
      {
         //static unsigned count;
         //fprintf(stderr, "JIT region #%u\n", ++count);
         block = jit_region(hash, word_pc, end - word_pc);
         //fprintf(stdout, "jit compile #%u reuse: %u exec: %u \n", ++countcomp, countre, countex);
      }
    }
    block(this, &state);
    //countex++;
}

ReturnMode CPU::run()
{
   for (;;)
   {
      invalidate_code();
      call_stack_ptr = 0;
#ifdef _WIN32
      auto ret = static_cast<ReturnMode>(setjmp(env));
#else
      auto ret = static_cast<ReturnMode>(sigsetjmp(env, 0));
#endif

      switch (ret)
      {
         case MODE_ENTER:
            enter(state.pc);
            break;

         case MODE_BREAK:
            *state.cp0.cr[CP0_REGISTER_SP_STATUS] |= SP_STATUS_BROKE | SP_STATUS_HALT;
            if (*state.cp0.cr[CP0_REGISTER_SP_STATUS] & SP_STATUS_INTR_BREAK)
               *state.cp0.irq |= 1;
#ifndef PARALLEL_INTEGRATION
            print_registers();
#endif
            return MODE_BREAK;

         case MODE_CHECK_FLAGS:
         case MODE_DMA_READ:
            return ret;

         default:
            break;
      }
   }
}
}
