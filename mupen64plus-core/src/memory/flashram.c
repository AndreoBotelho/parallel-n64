/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *   Mupen64plus - flashram.c                                              *
 *   Mupen64Plus homepage: http://code.google.com/p/mupen64plus/           *
 *   Copyright (C) 2002 Hacktarux                                          *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.          *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "memory.h"
#include "flashram.h"

#include "r4300/r4300.h"

#include "api/m64p_types.h"
#include "api/callbacks.h"
#include "main/main.h"
#include "main/rom.h"
#include "main/util.h"
#include "../pi/pi_controller.h"

Flashram_info flashram_info;
save_memory_data saved_memory;

static int flashram_inited = 0;

static void flashram_format(uint8_t *mem)
{
   if (flashram_inited != 0)
      return;
   memset(mem, 0xff, FLASHRAM_SIZE);
   flashram_inited = 1;
}

void init_flashram(void)
{
   flashram_info.mode = FLASHRAM_MODE_NOPES;
   flashram_info.status = 0;
}

uint32_t flashram_status(void)
{
   return (uint32_t) (flashram_info.status >> 32);
}

void flashram_command(uint32_t command)
{
   switch (command & 0xff000000)
   {
      case 0x4b000000:
         flashram_info.erase_offset = (command & 0xffff) * 128;
         break;
      case 0x78000000:
         flashram_info.mode = FLASHRAM_MODE_ERASE;
         flashram_info.status = 0x1111800800c20000LL;
         break;
      case 0xa5000000:
         flashram_info.erase_offset = (command & 0xffff) * 128;
         flashram_info.status = 0x1111800400c20000LL;
         break;
      case 0xb4000000:
         flashram_info.mode = FLASHRAM_MODE_WRITE;
         break;
      case 0xd2000000:  // execute
         switch (flashram_info.mode)
         {
            case FLASHRAM_MODE_NOPES:
            case FLASHRAM_MODE_READ:
               break;
            case FLASHRAM_MODE_ERASE:
               {
                  uint32_t i;
                  for (i=flashram_info.erase_offset; i<(flashram_info.erase_offset+128); i++)
                  {
                     flashram_info.mem[i^S8] = 0xff;
                  }
               }
               break;
            case FLASHRAM_MODE_WRITE:
               {
                  int i;
                  for (i=0; i<128; i++)
                  {
                     flashram_info.mem[(flashram_info.erase_offset+i)^S8]=
                        ((uint8_t*)g_rdram)[(flashram_info.write_pointer+i)^S8];
                  }
               }
               break;
            case FLASHRAM_MODE_STATUS:
               break;
            default:
               DebugMessage(M64MSG_WARNING, "unknown flashram command with mode:%x", (int)flashram_info.mode);
               stop=1;
               break;
         }
         flashram_info.mode = FLASHRAM_MODE_NOPES;
         break;
      case 0xe1000000:
         flashram_info.mode = FLASHRAM_MODE_STATUS;
         flashram_info.status = 0x1111800100c20000LL;
         break;
      case 0xf0000000:
         flashram_info.mode = FLASHRAM_MODE_READ;
         flashram_info.status = 0x11118004f0000000LL;
         break;
      default:
         DebugMessage(M64MSG_WARNING, "unknown flashram command: %x", (int)command);
         break;
   }
}

void dma_read_flashram(void)
{
   uint32_t i;

   flashram_format(&flashram_info.mem);

   switch (flashram_info.mode)
   {
      case FLASHRAM_MODE_STATUS:
         g_rdram[g_pi.regs[PI_DRAM_ADDR_REG]/4] = (uint32_t)(flashram_info.status >> 32);
         g_rdram[g_pi.regs[PI_DRAM_ADDR_REG]/4+1] = (uint32_t)(flashram_info.status);
         break;
      case FLASHRAM_MODE_READ:
         for (i=0; i<(g_pi.regs[PI_WR_LEN_REG] & 0x0FFFFFF)+1; i++)
         {
            ((uint8_t*)g_rdram)[(g_pi.regs[PI_DRAM_ADDR_REG]+i)^S8]=
               flashram_info.mem[(((g_pi.regs[PI_CART_ADDR_REG]-0x08000000)&0xFFFF)*2+i)^S8];
         }
         break;
      default:
         DebugMessage(M64MSG_WARNING, "unknown dma_read_flashram: %x", flashram_info.mode);
         stop=1;
         break;
   }
}

void dma_write_flashram(void)
{
   flashram_format(&flashram_info.mem);

   switch (flashram_info.mode)
   {
      case FLASHRAM_MODE_WRITE:
         flashram_info.write_pointer = g_pi.regs[PI_DRAM_ADDR_REG];
         break;
      default:
         DebugMessage(M64MSG_ERROR, "unknown dma_write_flashram: %x", flashram_info.mode);
         stop=1;
         break;
   }
}
