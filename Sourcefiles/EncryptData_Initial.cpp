// EncryptData.cpp
//
// This file uses the input data and key infhercmation to encrypt the input data
//
//test
#include "Main.h"

//////////////////////////////////////////////////////////////////////////////////////////////////
// code to encrypt the data as specified by the project assignment
int encryptData(char *data, int dataLength)
{
	int resulti = 0;
	gdebug1 = 0;					// a couple of global variables that could be used for debugging
	gdebug2 = 0;					// also can have a breakpoint in C code
	int iMilestoneXor = 1;

	// You can not declare any local variables in C, but should use resulti to indicate any errors
	// Set up the stack frame and assign variables in assembly if you need to do so
	// access the parameters BEFORE setting up your own stack frame
	// Also, you cannot use a lot of global variables - work with registers

	__asm {
		// you will need to reference some of these global variables
		// (gptrPasswordHash or gPasswordHash), (gptrKey or gkey), gNumRounds

		/* simple example that xors 2nd byte of data with 14th byte in the key file
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
		xor byte ptr [edi+1],al		// Exclusive-or the 2nd byte of data with the 14th eleherct of the keyfile
		// NOTE: Keyfile[14] = 0x21, that value changes the case of a letter and flips the LSB
		// Capital "B" = 0x42 becomes lowercase "c" since 0x42 xor 0x21 = 0x63
		//*/

		//*

		xor ecx, ecx;               // zero ecx for counter
		mov ebx, dataLength;        // move dataLength into ebx

		lea esi, gkey				// put the ADDRESS of gkey into esi
			mov esi, gptrKey;			// put the ADDRESS of gkey into esi (since *gptrKey = gkey)

		lea	esi, gPasswordHash		// put ADDRESS of gPasswordHash into esi
			mov esi, gptrPasswordHash	// put ADDRESS of gPasswordHash into esi (since unsigned char *gptrPasswordHash = gPasswordHash)

			mov edi, data;              // put ADDRESS of data into edi


		//sets counter to 0
		SWAP_HALF_NIBBLE :					//beginning of loop
		xor edx, edx
			xor eax, eax
			mov al, byte ptr[edi + ecx]
			shl al, 2
			and al, 0xcc
			or dl, al
			mov al, byte ptr[edi + ecx]
			shr al, 2
			and al, 0x33
			or dl, al
			mov byte ptr[edi + ecx], dl
		inc ecx;					// increments the counter
		cmp ecx, ebx
		jl SWAP_HALF_NIBBLE					//end of loop
		
		//Rotate bit right
		xor ecx, ecx;					// resets counter
	ROTATE_ONE_BIT:						// beginning of loop
		xor eax, eax
			mov al, byte ptr[edi + ecx]		// same as above function
			ror al, 1					// rotates the bits of al registers data to the right
			mov byte ptr[edi + ecx], al // moves the data back to the data location
			inc ecx;					// increments the counter
		cmp ecx, ebx;					// checks if end of data lenght is reached and exits if so
		jl ROTATE_ONE_BIT				//end of loop


			//reverse bit
			xor ecx, ecx				//reset counter
		REVERSE_BIT :					// beginning of loop
		xor eax, eax					// sets eax register to be 0 for data storage
			xor edx, edx					// set edx register to be 0 for data storage
			xor dl, dl					// sets dl register to be 0 for data storage
			mov dl, byte ptr[edi + ecx]	// moves a byte of data to the dl register
			mov al, dl					//moves the dl register data to al register
			xor ah, ah					//xor ah register to use as a counter beginning at 0
			mov ah, 8					//sets the inner loop counter to be 8

		Loop1:							//beginning of inner loop
		rcl al, 1						//rotates the bits with carry to the left by 1 in al register
			rcr dl, 1					// rotates the bits with carry to the right in dl register
			dec ah						// decrements the inner loop counter by 1
			jnz Loop1					// loops as long as the inner loop counter != 0
			mov byte ptr[edi + ecx], dl // moves the dl register data back to the data location
			inc ecx						// increments the outer loop counter and checks if end of data has been reached, if so exits
			cmp ecx, ebx
			jl REVERSE_BIT				//end of loop


			// look up table
			xor ecx, ecx					//sets counter to 0
		LOOK_UP_TABLE :   // beginning of loop
		xor edx, edx				// set edx register to be 0 for data storage
			mov dl, byte ptr[edi + ecx] //same as other loop above
			mov al, [gEncodeTable + edx] // exhanges the table value with the table variable and moves it to al register 
			mov byte ptr[edi + ecx], al // moves the byte of data back to the data location
			inc ecx						// same as above loop
			cmp ecx, ebx
			jl LOOK_UP_TABLE			//end of loop


			//Swap Nibble
			xor ecx, ecx				//sets counter to 0
		SWAP_NIBBLE :					//beginning of loop
		xor eax, eax
			xor edx, edx
			movzx eax, byte ptr[edi + ecx]
			movzx edx, byte ptr[edi + ecx]	//moves a byte of data at the next data location into ah register
			and al, 0xF0					// swaps the position of the two in Ax "DATA [ah,al] -> [al,ah]"
			rol al, 4					// rotates the al registers bits 4 times to the left				// rotates the ah registers bits 4 times to the left
			and dl, 0x0F						//decrements the counter
			ror dl, 4	//moves the al data back into the previous data location
			or eax, edx					//increments the counter
			mov byte ptr[edi + ecx], al // moves the data from the ah register into the current data location
			inc ecx
			cmp ecx, ebx;				// checks for end of data lenght and exits if so
		jl SWAP_NIBBLE					//end of loop
		
	}

	return resulti;
} // encryptData