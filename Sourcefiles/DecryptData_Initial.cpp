// DecryptData.cpp
//
// THis file uses the input data and key information to decrypt the input data
//

#include "Main.h"

//////////////////////////////////////////////////////////////////////////////////////////////////
// code to decrypt the data as specified by the project assignment
int decryptData(char *data, int dataLength)
{
	int resulti = 0;

	gdebug1 = 0;					// a couple of global variables that could be used for debugging
	gdebug2 = 0;					// also can have a breakpoint in C code

	// You can not declare any local variables in C, but should use resulti to indicate any errors
	// Set up the stack frame and assign variables in assembly if you need to do so
	// access the parameters BEFORE setting up your own stack frame
	// Also, you cannot use a lot of global variables - work with registers

	__asm {
		// you will need to reference some of these global variables
		// (gptrPasswordHash or gPasswordHash), (gptrKey or gkey), gNumRounds

        /*
		// simple example that xors 2nd byte of data with 14th byte in the key file
		lea esi,gkey				// put the ADDRESS of gkey into esi
		mov esi,gptrKey;			// put the ADDRESS of gkey into esi (since *gptrKey = gkey)

		lea	esi,gPasswordHash		// put ADDRESS of gPasswordHash into esi
		mov esi,gptrPasswordHash	// put ADDRESS of gPasswordHash into esi (since unsigned char *gptrPasswordHash = gPasswordHash)

		mov al,byte ptr [esi]				// get first byte of password hash
		mov al,byte ptr [esi+4]				// get 5th byte of password hash
		mov ebx,2
		mov al,byte ptr [esi+ebx]			// get 3rd byte of password hash
		mov al,byte ptr [esi+ebx*2]			// get 5th byte of password hash

		mov ax,word ptr [esi+ebx*2]			// gets 5th and 6th bytes of password hash ( gPasswordHash[4] and gPasswordHash[5] ) into ax
		mov eax,dword ptr [esi+ebx*2]		// gets 4 bytes, as in:  unsigned int X = *( (unsigned int*) &gPasswordHash[4] );

		mov al,byte ptr [gkey+ebx]			// get's 3rd byte of gkey[] data

		mov al,byte ptr [gptrKey+ebx]		// THIS IS INCORRECT - will add the address of the gptrKey global variable (NOT the value that gptrKey holds)

		mov al,byte ptr [esi+0xd];			// access 14th byte in gkey[]: 0, 1, 2 ... d is the 14th byte
		mov edi,data				// Put ADDRESS of first data element into edi
		xor byte ptr [edi+1],al		// Exclusive-or the 2nd byte of data with the 14th element of the keyfile
									// NOTE: Keyfile[14] = 0x21, that value changes the case of a letter and flips the LSB
									// Lowercase "c" = 0x63 becomes capital "B" since 0x63 xor 0x21 = 0x42
        //*/
        //*

        xor ecx, ecx;               // zero ecx for counter
        mov ebx, dataLength;        // move dataLength into ebx

        lea esi, gkey				// put the ADDRESS of gkey into esi
            mov esi, gptrKey;			// put the ADDRESS of gkey into esi (since *gptrKey = gkey)

        lea	esi, gPasswordHash		// put ADDRESS of gPasswordHash into esi
            mov esi, gptrPasswordHash	// put ADDRESS of gPasswordHash into esi (since unsigned char *gptrPasswordHash = gPasswordHash)

            mov edi, data;              // put ADDRESS of data into edi

	SWAP_HALF_NIBBLE:
		
		mov al, byte ptr[edi + ecx]
			inc ecx
			cmp ecx, ebx;
		jl END2
		mov ah, byte ptr[edi + ecx]
			xchg ah, al
			ror al, 2
			ror ah, 2
			dec ecx
			mov byte ptr[edi + ecx], al
			inc ecx
			mov byte ptr[edi + ecx], ah
		cmp ecx, ebx;
		jl SWAP_HALF_NIBBLE
		END2 :

		xor ecx,ecx
	ROTATE_ONE_BIT :
		mov al, byte ptr[edi + ecx]
		ror al, 1
		mov byte ptr[edi + ecx], al
		inc ecx;
		cmp ecx, ebx;
		jl ROTATE_ONE_BIT

			//reverse bit
			xor ecx, ecx
		REVERSE_BIT :

			xor al, al
			xor dl, dl
			mov dl, byte ptr[edi + ecx]

			mov al, dl

			xor ah, ah
			mov ah, 8

			Loop2:
				rcr al, 1
				rcl dl, 1
				dec ah
				jnz Loop2

				mov al, dl

				mov byte ptr[edi + ecx], al

			inc ecx
			cmp ecx, ebx;
		jl REVERSE_BIT
		
			// look up table
			
			xor ecx, ecx
	SWAP_NIBBLE:
		mov al, byte ptr[edi + ecx]
			inc ecx
			cmp ecx, ebx;
		jl END1
			mov ah, byte ptr[edi + ecx]
			xchg ah, al
			ror al, 4
			ror ah, 4
			dec ecx
			mov byte ptr[edi + ecx], al
			inc ecx
			mov byte ptr[edi + ecx], ah
			cmp ecx, ebx;
		jl SWAP_NIBBLE
		END1 :
		/*
    XOR_ONE_LOOP:                   // loop label
        mov al, byte ptr[edi + ecx];// takes the value at edi + ecx (which is our counter that we zero'd above) and moves it to al
        xor al, 1;                  // xor al by 1
        mov byte ptr[edi + ecx], al;// takes our xor'd value from al, and puts it back into where we found it (edi + eax)
        inc ecx;                    // increment our counter ecx
        cmp ecx, ebx;               // compare the value of counter against ebx, which we set to dataLength above
        jl XOR_ONE_LOOP;            // loops to label if ecx is LESS THAN ebx, so it basically loops through the entire input file
                                    //*/
	}

	return resulti;
} // decryptData

