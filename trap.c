#include "types.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"
#include "x86.h"
#include "traps.h"
#include "spinlock.h"

// Declaration for mappages (defined in vm.c)
int mappages(pde_t *pgdir, void *va, uint size, uint pa, int perm);

// Interrupt descriptor table (shared by all CPUs).
struct gatedesc idt[256];
extern uint vectors[];  // in vectors.S: array of 256 entry pointers
struct spinlock tickslock;
uint ticks;

void
tvinit(void)
{
  int i;

  for(i = 0; i < 256; i++)
    SETGATE(idt[i], 0, SEG_KCODE<<3, vectors[i], 0);
  SETGATE(idt[T_SYSCALL], 1, SEG_KCODE<<3, vectors[T_SYSCALL], DPL_USER);
  
  initlock(&tickslock, "time");
}

void
idtinit(void)
{
  lidt(idt, sizeof(idt));
}

//PAGEBREAK: 41
void
trap(struct trapframe *tf)
{
  if(tf->trapno == T_SYSCALL){
    if(proc->killed)
      exit();
    proc->tf = tf;
    syscall();
    if(proc->killed)
      exit();
    return;
  }
 // CS 3320 project 2
 // Lazy page allocation handling
 if(tf->trapno == T_PGFLT){
    extern int page_allocator_type;
    uint faulting_va;
    char *mem;
    uint page_va;

    faulting_va = rcr2();  // Get the faulting virtual address

    // Only handle page fault for lazy allocator
    if(page_allocator_type == 1 && proc != 0){
      // Round down to page boundary
      page_va = PGROUNDDOWN(faulting_va);

      // Check if the faulting address is within the valid heap range
      // Valid range: from PGSIZE (first page is guard page) to proc->sz
      if(page_va >= PGSIZE && page_va < proc->sz){
        // Allocate a physical page
        mem = kalloc();
        if(mem == 0){
          cprintf("Unhandled page fault!\n");
        } else {
          // Clear the page
          memset(mem, 0, PGSIZE);

          // Map the page with user read/write permissions
          if(mappages(proc->pgdir, (char*)page_va, PGSIZE, v2p(mem), PTE_W|PTE_U) < 0){
            cprintf("Unhandled page fault!\n");
            kfree(mem);
          } else {
            // Successfully handled the page fault, return
            return;
          }
        }
      } else {
        // Address is outside valid range
        cprintf("Unhandled page fault!\n");
      }
    } else {
      // Default allocator or not a process context
      cprintf("Unhandled page fault!\n");
    }
 }


  switch(tf->trapno){
  case T_IRQ0 + IRQ_TIMER:
    if(cpu->id == 0){
      acquire(&tickslock);
      ticks++;
      wakeup(&ticks);
      release(&tickslock);
    }
    lapiceoi();
    break;
  case T_IRQ0 + IRQ_IDE:
    ideintr();
    lapiceoi();
    break;
  case T_IRQ0 + IRQ_IDE+1:
    // Bochs generates spurious IDE1 interrupts.
    break;
  case T_IRQ0 + IRQ_KBD:
    kbdintr();
    lapiceoi();
    break;
  case T_IRQ0 + IRQ_COM1:
    uartintr();
    lapiceoi();
    break;
  case T_IRQ0 + 7:
  case T_IRQ0 + IRQ_SPURIOUS:
    cprintf("cpu%d: spurious interrupt at %x:%x\n",
            cpu->id, tf->cs, tf->eip);
    lapiceoi();
    break;
   
  //PAGEBREAK: 13
  default:
    if(proc == 0 || (tf->cs&3) == 0){
      // In kernel, it must be our mistake.
      cprintf("unexpected trap %d from cpu %d eip %x (cr2=0x%x)\n",
              tf->trapno, cpu->id, tf->eip, rcr2());
      panic("trap");
    }
    // In user space, assume process misbehaved.
    cprintf("pid %d %s: trap %d err %d on cpu %d "
            "eip 0x%x addr 0x%x--kill proc\n",
            proc->pid, proc->name, tf->trapno, tf->err, cpu->id, tf->eip, 
            rcr2());
    proc->killed = 1;
  }

  // Force process exit if it has been killed and is in user space.
  // (If it is still executing in the kernel, let it keep running 
  // until it gets to the regular system call return.)
  if(proc && proc->killed && (tf->cs&3) == DPL_USER)
    exit();

  // Force process to give up CPU on clock tick.
  // If interrupts were on while locks held, would need to check nlock.
  if(proc && proc->state == RUNNING && tf->trapno == T_IRQ0+IRQ_TIMER)
    yield();

  // Check if the process has been killed since we yielded
  if(proc && proc->killed && (tf->cs&3) == DPL_USER)
    exit();
}
