// This file is part of KEmuFuzzer.
// 
// KEmuFuzzer is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
// 
// KEmuFuzzer is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
// details.
// 
// You should have received a copy of the GNU General Public License along with
// KEmuFuzzer.  If not, see <http://www.gnu.org/licenses/>.


#define STACK_SIZE		0x4000

	.text
.globl _start, start
	.type	start, @function
	.type	_start, @function
start:	
_start:
	mov 	$(loaderstack + 0x2000), %esp	;
	push	$0
	popf	
	push	%ebx		;
	push	%eax		;
	call	init		;
endless:
	hlt
	jmp	endless		;
	.lcomm   loaderstack, STACK_SIZE
