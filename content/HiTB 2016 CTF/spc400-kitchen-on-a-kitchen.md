Title: spc400 - Kitchen on a kitchen
Date: 2016-05-29 19:53
Author: doskop
Tags: CTF

## Introduction

> Kitchens come in many shapes and sizes, some more surprising than
> others. One of our resident chefs has taken some common kitchen
> instruments and used them to create a Kitchen on a Kitchen. Do you
> have the skills to adapt to its style? Try the kitchen here:
> http://145.111.225.73/

> Flag format is "HITB{" + md5(answer) + "}"

I've created a mirror [here]({filename}/downloads/hitb-2016-ctf/spc400/live/index.html).

## Analysis

Opening the challenge's web page show us a very retro-looking screen that builds up slowly so it's probably some form of emulator or virtual machine that runs in javascript. Once you enter 8 characters you'll see 'CODE WRONG'.

Looking at the source (take a peek at [core2.js]({filename}downloads/hitb-2016-ctf/spc400/live/core2.js)) confirms this is an emulator but the source is quite obfuscated: most variable names are replaced with large chains of kitchen instruments and ingredients. I chose to manually reverse engineer some proper variable names and ended up with this [cleaned up version]({filename}/downloads/hitb-2016-ctf/spc400/live/core2_clean.js).

## Exploitation

Ok, so now we have a relatively clean source code, how do we attack it? The method I chose was to add some extra code to the comperator operators which if either side is 65 (the character code of the 'A' key) and the other side isn't 0 it will log the value of the other side. Here's the code for the comperator log functions:

    :::javascript
    this.log_cmp_left = function(left, right) {
        if (left == 65 && right) {
            console.log('Char:', right, String.fromCharCode(right));
            return right;
        }
        return left;
    }

    this.log_cmp_right = function(left, right) {
        if (right == 65 && left) {
            console.log('Char:', left, String.fromCharCode(left));
            return left;
        }
        return right;
    }

Next, we patch the comperator opcodes 0x04 and 0x05 (starting around line 340):

	:::javascript
    case 0x04:
         srcreg2 = itype['srcreg2'];
         srcreg1 = itype['srcreg1'];
         imm = itype['imm'];

         tmp_inst = this.load_32(this.PC + 4);
         next_inst = this.decode_inst(tmp_inst);
         this.exec_inst(next_inst, true);

         this.registers[srcreg2] = this.log_cmp_left(this.registers[srcreg2], this.registers[srcreg1]);

		this.registers[srcreg1] = this.log_cmp_right(this.registers[srcreg2], this.registers[srcreg1]);

		if (this.registers[srcreg2] == this.registers[srcreg1]) {
             if ((imm >> 15) & 1) {
                 this.PC -= Math.abs(imm | 0xffff0000) * 4;
             } else {
                 this.PC += (imm * 4);
             }
         } else {
             this.PC += 4;
         }
         break;


    case 0x05:
        srcreg2 = itype['srcreg2'];
        srcreg1 = itype['srcreg1'];
        imm = itype['imm'];

        tmp_inst = this.load_32(this.PC + 4);
        next_inst = this.decode_inst(tmp_inst);
        this.exec_inst(next_inst, true);

        this.registers[srcreg2] = this.log_cmp_left(this.registers[srcreg2], this.registers[srcreg1]);

		this.registers[srcreg1] = this.log_cmp_right(this.registers[srcreg2], this.registers[srcreg1]);

		if (this.registers[srcreg2] != this.registers[srcreg1]) {
            if ((imm >> 15) & 1) {
            	this.PC -= Math.abs(imm | 0xffff0000) * 4;
            } else {
	            this.PC += (imm * 4);
            }
        } else {
            this.PC += 4;
        }
        break;

Now, we reload the page (or go [here]({filename}/downloads/hitb-2016-ctf/spc400/cracked/index.html)), enter the letter 'a' 8 times and observe the "CODE OK :)" message and the log messages in the console:

    core2_crack.js:117 Char: 66 B
    core2_crack.js:117 Char: 49 1
    core2_crack.js:117 Char: 78 N
    core2_crack.js:117 Char: 52 4
    core2_crack.js:117 Char: 87 W
    core2_crack.js:117 Char: 51 3
    core2_crack.js:117 Char: 66 B
    core2_crack.js:117 Char: 90 Z

So we now know the password is *B1N4W3BZ*.