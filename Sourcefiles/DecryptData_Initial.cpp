// DecryptData.cpp
//
// THis file uses the input data and key infhercrmation to decrypt the input data
//

#include "Main.h"

//////////////////////////////////////////////////////////////////////////////////////////////////
// code to decrypt the data as specified by the project assignment
int decryptData(char *data, int dataLength)
{
	int resulti = 0;
	gdebug1 = 0;					// a couple of global variables that could be used for debugging
	gdebug2 = 0;					// also can have a breakpoint in C code

	__asm {
									// The decryption effectively reverses every step the encryption algorithm does and starting with the end step
										
		NUM_rounds:					// hopcount loop begin		
		
		xor ecx, ecx;               // zero ecx for counter
		mov ebx, dataLength;        // move dataLength into ebx

		lea esi, gkey				// put the ADDRESS of gkey into esi
			mov esi, gptrKey;			// put the ADDRESS of gkey into esi (since *gptrKey = gkey)

		lea	esi, gPasswordHash		// put ADDRESS of gPasswordHash into esi
			mov esi, gptrPasswordHash	// put ADDRESS of gPasswordHash into esi (since unsigned char *gptrPasswordHash = gPasswordHash)

			mov edi, data;         // put ADDRESS of data into edi
		
										//Swap Nibble
										//sets counter to 0
	SWAP_NIBBLE:						//Swap Nibble - beginning of loop
			xor eax, eax				// "CLEAR REG EAX" for storage	
			xor edx, edx				// "CLEAR REG ECX" for storage
			movzx eax, byte ptr[edi + ecx]	// gets a byte of data from the data array with the help of ecx as a incrementor and puts it in eax with zero extention of upper register
			movzx edx, byte ptr[edi + ecx]	// same as above but with edx register
			and al, 0xF0					// logic AND of the lower eax register to clear the bits for rotation
			ror al, 4					// rotates the al registers bits 4 times to the right			
			and dl, 0x0F				// logic AND of the lower edx register to clear the bits for rotation
			rol dl, 4					// rotates the dl registers bits 4 times to the left
			or eax, edx					// logic OR the edx and eax register swapping the nibbles in eax
			mov byte ptr[edi + ecx], al // moves the data from the al register back into the current data array location
			inc ecx						// increments the counter
			cmp ecx, ebx;				// checks for end of data lenght and exits if so exits
		jl SWAP_NIBBLE					// swap nibble - end of loop

										// look up table
			xor ecx, ecx				//sets counter to 0
		LOOK_UP_TABLE :	                // look up table - beginning of loop
		xor edx, edx					// sets edx register to be 0 for data storage
			mov dl, byte ptr[edi + ecx]	//same as other loop above
			mov al, [gDecodeTable + edx]// exhanges the table value with the table variable and moves it to al register 
			mov byte ptr[edi + ecx], al	// moves the byte of data back to the data location
			inc ecx						// same as above loop
			cmp ecx, ebx
			jl LOOK_UP_TABLE			// look up table - end of loop

										//Reverse bit
			xor ecx, ecx				//reset counter
		REVERSE_BIT :					// Reverse bit - beginning of loop
		xor eax, eax					// sets eax register to be 0 for data storage
			xor edx, edx                // sets edx register to be 0 for data storage
			mov dl, byte ptr[edi + ecx] // moves a byte of data to the dl register
			mov al, dl					//moves the dl register data to al register
			xor ah, ah					//xor ah register to use as a counter beginning at 0
			mov ah, 8					//sets the inner loop counter to be 8

		Loop1:							//beginning of inner loop
		rcr al, 1						//rotates the bits with carry to the right by 1 in al register
			rcl dl, 1					// rotates the bits with carry to the left in dl register
			dec ah						// decrements the inner loop counter by 1
			jnz Loop1					// loops as long as the inner loop counter != 0
			mov byte ptr[edi + ecx], dl // moves the dl register data back to the data location
			inc ecx						// increments the outer loop counter and checks if end of data has been reached, if so exits
			cmp ecx, ebx
			jl REVERSE_BIT				// Reverse bit - end of loop

										// Rotate bit right
			xor ecx, ecx				// resets counter
		ROTATE_ONE_BIT :				// beginning of loop
		xor eax, eax					// set eax register to 0 for data storage
			mov al, byte ptr[edi + ecx]	// same as above function
			rol al, 1					// rotates the bits of al registers data to the left 1 time
			mov byte ptr[edi + ecx], al	// moves the data back to the data location
			inc ecx;					// increments the counter
		cmp ecx, ebx;					// checks if end of data lenght is reached and exits if so
		jl ROTATE_ONE_BIT				// Rotate one bit - end of loop
			
												// Swap half nibble - beginning of loop
			xor ecx,ecx							// resets counter
			SWAP_HALF_NIBBLE :					// Swap half nibble - beginning of loop
			xor edx, edx						// "CLEAR REG EDX" for storage
				xor eax, eax					// "CLEAR REG EAX" for storage
				mov al, byte ptr[edi + ecx]     // stores the byte at data pointer array edi and index/count ecx into al register
				shr al, 2						// shifts the al register right by 2 
				and al, 0x33                    // logic AND the data clearing the lower 2 bits of al & ah register
				or dl, al						// logic OR the al and dl register to copy and clear any 0->0 bits
				mov al, byte ptr[edi + ecx]     // resets the data value stored in al before shifting
				shl al, 2						// shifts the al register left by 2 
				and al, 0xcc					// logic AND the al register by clearing the two upper bits of the al & ah register
				or dl, al						// logic OR the dl and al register again to swap the nibbles
				mov byte ptr[edi + ecx], dl		// moves the value back into the data array
			inc ecx								// increments the counter and compares if its incremented past the size of the data array
			cmp ecx, ebx;						// checks for end of data lenght and exits if so
			jl SWAP_HALF_NIBBLE					//swap half nibble - end of loop
				


			xor ecx, ecx;               // zero ecx for counter
			mov ebx, dataLength;        // move dataLength into ebx

			lea edi, gkey				// put the ADDRESS of gkey into esi
				mov edi, gptrKey;			// put the ADDRESS of gkey into esi (since *gptrKey = gkey)

			lea	esi, gPasswordHash		// put ADDRESS of gPasswordHash into esi
				mov esi, gptrPasswordHash	// put ADDRESS of gPasswordHash into esi (since unsigned char *gptrPasswordHash = gPasswordHash)
			
				mov ecx, gNumRounds     // moves the last round count to ecx register which is used as a incrementor to get the correct byte values from the gPasswordHash
				dec ecx					// decrements ecx to align the gNumRounds value correctly since it is always > 1
				mov gNumRounds, ecx     // moves the value back into the round count

				//hopcount

				mov edx, data           // moves the data pointer to edx register so edx can be used as a pointer to get values in the data array
				mov ebx, edx			// stores the edx pointer to ebx
				add ebx, dataLength     // increments ebx to get the end of the data array
				xor eax, eax			// "CLEAR REG EAX" for storage
			mov ah, byte ptr[esi + 2 + ecx * 4]  // gets the hop count of the hop function the first time being initalized and after that the [2 + round * 4] round = nth term
			mov al, byte ptr[esi + 3 + ecx * 4]  // gets the hop count of the hop function the first time being initalized and after that the [3 + round * 4] round = nth term

			mov ghopindex, eax;			 // stores eax which has both hop counts in its ah,al register and a cleared upper 16 bit reg in ghopindex global variable effectivly creating the hopcount of [2 + round * 4] * 256 + [3 + round * 4] which is already in eax register

			xor eax, eax				 // "CLEAR REG EAX" for count & storage
			mov ah, byte ptr[esi + ecx * 4]		// gets the start point of the hop function the first time being initalized and after that the [0 + round * 4] round = nth term
			mov al, byte ptr[esi + 1 + ecx * 4] // gets the start point of the hop function the first time being initalized and after that the [1 + round * 4] round = nth term

			mov gkeyindex,eax			// stores eax which has both start points in its ah,al register and a cleared upper 16 bit reg in gkeyindex global variable effectivly creating the start index of [2 + round * 4] * 256 + [3 + round * 4] which is already in eax register
										// since we already have gkeyindex set to eax we don't really need to do this however it makes it easier to reference and remember what is in eax when looking at the hop count inner loop

		next_data :						// hopcount inner loop
			
			xor ecx, ecx				// "CLEAR REG ECX" for storage
			mov cl, byte ptr[edx]		// uses the lower register of ecx which is cl to store a byte of data with help of edx register which has the pointer data
			xor cl, byte ptr[edi + eax] // xor (masks) the data collected with the gkeyindex [eax] and the gkey array pointer [edi] 
			mov byte ptr [edx], cl		// stores the byte back into the same data array after operation finished

			inc edx						// increments edx which is the next byte of data to be accessed
			cmp edx, ebx				// checks if the end of the data array has been reached and exits the inner loop if so
			je exit_encrypt

			add eax, ghopindex			// Increments the gkeyindex with the ghopindex
			cmp eax, 65537				// compares if the two are larger than the value 65537
			jb next_data				// if not then it loops again
			sub eax, 65537				// if larger then it subtracts 65537 to not get a out of bounds error and loops again
			jmp next_data

			exit_encrypt :
				mov ecx, gNumRounds		// restores the current round back into ecx (outer loop counter & round)
				cmp ecx, 0				 // compares the round provided by the user to 0 and if equal exits the outer loop of the hop count
				jne NUM_rounds

				//end hop
	}
	
	return resulti;
} // decryptData