    .data
        PromptForPlaintext:
            .asciz "Please enter the plaintext: "
            lenPromptForPlaintext = .-PromptForPlaintext
        PromptForShiftValue:
            .asciz "Please enter the shift value: "
            lenPromptForShiftValue = .-PromptForShiftValue
        Newline:
            .asciz "\n"
        ShiftValue:
            .int 0
    .bss
        .comm buffer, 102       # Buffer to read in plaintext/output ciphertext
        .comm intBuffer, 4      # Buffer to read in shift value
                            # (assumes value is 3 digits or less)
    .text
        .globl _start

        .type PrintFunction, @function
        .type ReadFromStdin, @function
        .type GetStringLength, @function
        .type AtoI, @function
        .type CaesarCipher, @function

        PrintFunction:
            pushl %ebp              # store the current value of EBP on the stack
            movl %esp, %ebp         # Make EBP point to top of stack
    
            # Write syscall
            movl $4, %eax           # syscall number for write()
            movl $1, %ebx           # file descriptor for stdout
            movl 8(%ebp), %ecx      # Address of string to write
            movl 12(%ebp), %edx     # number of bytes to write
            int $0x80
            movl %ebp, %esp         # Restore the old value of ESP
            popl %ebp               # Restore the old value of EBP
            ret                     # return

        ReadFromStdin:
            pushl %ebp              # store the current value of EBP on the stack
            movl %esp, %ebp         # Make EBP point to top of stack
            # Read syscall
            movl $3, %eax           # syscall number for read()
            movl $0, %ebx           # file descriptor for stdin
            movl 8(%ebp), %ecx      # address of buffer to write input to
            movl 12(%ebp), %edx     # number of bytes to read
            int $0x80
            movl %ebp, %esp         # Restore the old value of ESP
            popl %ebp               # Restore the old value of EBP
            ret                     # return

        GetStringLength:
            # Strings which are read through stdin will end with a newline character (0xa)
            # So look through the string until we find the newline and keep a count
            pushl %ebp              # store the current value of EBP on the stack
            movl %esp, %ebp         # Make EBP point to top of stack
            
            movl 8(%ebp), %esi      # Store the address of the source string in esi
            
            xor %edx, %edx          # edx = 0
            Count:
                        inc %edx                # increment edx
                lodsb                   # load the byte at esi into eax and increment esi
                cmp $0xa, %eax           # compare the newline character vs eax
                jnz Count               # If eax != newline, loop back
    
            dec %edx                # the loop adds an extra one onto edx
            movl %edx, %eax         # return value
            
            movl %ebp, %esp         # Restore the old value of ESP
            popl %ebp               # Restore the old value of EBP
            ret                     # return

        
        AtoI:
            pushl %ebp              # save base pointer
            movl %esp, %ebp         # set new base pointer
            movl 8(%ebp), %esi      # load address of the string into esi
            xor %eax, %eax          # clear eax (result accumulator)
        
        AtoILoop:
            movb (%esi), %bl        # load byte at esi into bl
            cmpb $0xa, %bl          # check for newline character
            je AtoIDone             # if newline, end of input
            cmpb $0x00, %bl         # check for null terminator
            je AtoIDone             # if null terminator, end of input
            cmpb $'0', %bl          # compare bl with '0'
            jb AtoIDone             # if less than '0', invalid character
            cmpb $'9', %bl          # compare bl with '9'
            ja AtoIDone             # if greater than '9', invalid character
            subb $'0', %bl          # convert ASCII digit to numeric value
            imull $10, %eax         # multiply result by 10
            movzbl %bl, %ebx        # zero-extend bl into ebx
            addl %ebx, %eax         # add digit to result
            incl %esi               # move to next character
            jmp AtoILoop            # repeat loop
        
        AtoIDone:
            movl %ebp, %esp         # restore stack pointer
            popl %ebp               # restore base pointer
            ret                     # return

        CaesarCipher:
            pushl %ebp              # save base pointer
            movl %esp, %ebp         # set new base pointer
            pushl %ebx              # save ebx
            pushl %esi              # save esi
            pushl %edi              # save edi
            movl 8(%ebp), %esi      # load address of plaintext string into esi
            movl 12(%ebp), %ecx     # load shift value into ecx
            movl %ecx, %eax         # copy shift value to eax
            xorl %edx, %edx         # clear edx for division
            movl $26, %ebx          # ebx = 26 (number of letters in alphabet)
            divl %ebx               # edx = shift % 26
            movl %edx, %ecx         # ecx = shift % 26
        
        CipherLoop:
            movb (%esi), %al        # load byte from string into al
            cmpb $0xa, %al          # check for newline character
            
            je CipherDone           # if newline, end of string
            cmpb $0x00, %al         # check for null terminator
            
            je CipherDone           # if null terminator, end of string
            cmpb $'A', %al          # compare with 'A'
            
            jb SkipChar             # if less than 'A', skip character
            cmpb $'Z', %al
            
            jbe UpperCase           # if between 'A' and 'Z', uppercase letter
            cmpb $'a', %al
            
            jb SkipChar             # if less than 'a', skip character
            cmpb $'z', %al
            
            jbe LowerCase           # if between 'a' and 'z', lowercase letter
            jmp SkipChar            # if not a letter, skip
        
        UpperCase:
            subb $'A', %al          # convert to 0-25 range
            addb %cl, %al           # apply shift
            cmpb $26, %al           # check if wraparound is needed
            jb UpperNoWrap          # if al < 26, no wraparound needed
            subb $26, %al           # wrap around by subtracting 26
        
        UpperNoWrap:
            addb $'A', %al          # convert back to ASCII
            movb %al, (%esi)        # store shifted character back in string
            jmp NextChar            # proceed to next character
        
        LowerCase:
            subb $'a', %al          # convert to 0-25 range
            addb %cl, %al           # apply shift
            cmpb $26, %al           # check if wraparound is needed
            jb LowerNoWrap          # if al < 26, no wraparound needed
            subb $26, %al           # wrap around by subtracting 26
        
        LowerNoWrap:
            addb $'a', %al          # convert back to ASCII
            movb %al, (%esi)        # store shifted character back in string
            jmp NextChar            # proceed to next character
        SkipChar:
            # Non-alphabetic character, leave it unchanged
        
        NextChar:
            incl %esi               # move to next character
            jmp CipherLoop          # repeat loop
        
        CipherDone:
            popl %edi               # restore edi
            popl %esi               # restore esi
            popl %ebx               # restore ebx
            movl %ebp, %esp         # restore stack pointer
            popl %ebp               # restore base pointer
            ret                     # return

        _start:

            # Print prompt for plaintext
            pushl $lenPromptForPlaintext
            pushl $PromptForPlaintext
            call PrintFunction
            addl $8, %esp
            
            # Read the plaintext from stdin
            pushl $102
            pushl $buffer
            call ReadFromStdin
            addl $8, %esp
            
            # Print newline
            pushl $1
            pushl $Newline
            call PrintFunction
            addl $8, %esp
            
            # Get input string and adjust the stack pointer back after
            pushl $lenPromptForShiftValue
            pushl $PromptForShiftValue
            call PrintFunction
            addl $8, %esp
            
            # Read the shift value from stdin
            pushl $4
            pushl $intBuffer
            call ReadFromStdin
            addl $8, %esp
            
            # Print newline
            pushl $1
            pushl $Newline
            call PrintFunction
            addl $8, %esp
            
            # Convert the shift value from a string to an integer.
            pushl $intBuffer             # push address of shift value string
            call AtoI                    # call AtoI to convert string to integer
            addl $4, %esp                # clean up stack
            movl %eax, ShiftValue        # store the integer shift value in ShiftValue
            
            # Perform the caesar cipher
            movl ShiftValue, %eax        # load shift value into eax
            pushl %eax                   # push shift value onto stack
            pushl $buffer                # push address of plaintext buffer
            call CaesarCipher            # call CaesarCipher to encrypt plaintext
            addl $8, %esp                # clean up stack
            
            # Get the size of the ciphertext
            # The ciphertext must be referenced by the 'buffer' label
            pushl $buffer                # push address of ciphertext string
            call GetStringLength         # call GetStringLength to get length
            addl $4, %esp                # clean up stack
            
            # Print the ciphertext
            pushl %eax                   # push length of ciphertext
            pushl $buffer                # push address of ciphertext string
            call PrintFunction           # call PrintFunction to display ciphertext
            addl $8, %esp                # clean up stack
            
            # Print newline
            pushl $1
            pushl $Newline
            call PrintFunction
            addl $8, %esp

            # Exit the program
            Exit:
                movl $1, %eax                # syscall number for exit()
                movl $0, %ebx                # exit status 0
                int $0x80                    # make syscall
