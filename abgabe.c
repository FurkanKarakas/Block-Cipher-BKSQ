/*
	Name: Applied Cryptology Project
	Copyright: All rights reserved by the author. Only to be used in terms of classroom purposes.
	Author: Furkan Karakaþ
	Date: 31.05.18 16:34
	Description: Every function that I used in this project can be found below in my code.
*/

/*



	*****CHANGES MADE TO THE ORIJINAL STRUCTURE OF THE FUNCTIONS*****
	
	1) The arguments of "hmac" have been altered:
	
	from: (uint8_t const *data, uint32_t const data_length, uint8_t const *key, uint8_t * tag)
	
	to  : (uint8_t const *data, uint32_t const data_length, uint8_t const *key, uint32_t const key_length, uint8_t * tag, uint8_t * data_prefix, uint32_t const data_prefix_length)
	
	Summary: Additional two constant integers named "key_length" and "data_prefix_length" have been added.
	
	Reason for this change: To be able to store the size of the corresponding variables since we cannot determine the size of a pointer array in the function!
	
	- We do a sanity check on the key length whether it is of an appropriate size.
	- As we need the data_length as a parameter, we also need the length of the data_prefix as a parameter.
	
	The arguments of hmac in the "main.c" have been also altered accordingly.



*/



/** \file abgabe.c */


// Status Codes

#define BKSQ_ENCRYPT_OK 0 ///< Return value: BKSQ Encryption OK!
#define CTR_OK 0 ///< Return value: Counter Mode OK!

#define INVALID_DATA_LENGTH 1 ///< Error/Return value: data length no good, maybe missing padding
#define INVALID_NONCE_LENGTH 2 ///< Error/Return value: nonce length no good, maybe missing padding 

#define INVALID_KEY_LENGTH 3     // I defined this for checking the validity of the key

#define DM_OK 0 ///< Return value: Davies-Meyer-Hash OK!
#define HMAC_OK 0 ///< Return value: HMAC OK!

#define AE_ENC_OK 0 ///< Return value: Authenticated Encryption OK!

// Macros and Constants


#define BLOCKSIZE 96 ///< fix the BLOCKSIZE to 96 bits
#define BLOCKSIZE_BYTE (BLOCKSIZE+7)/8 ///< the BLOCKSIZE in bytes, for convenience only  
#define BLOCKCYPHER_ENCRYPT(in, key, out) bksq_encrypt(in, out, key) ///< dependeny injection, defining the block cypher used



/**
 * A data structure holding all information relevant for en/decryption
 */
typedef struct {
    uint8_t *data; ///< a pointer to the input data
    uint32_t data_length; ///< length of the input data in bits; must be a multiple of the blocklength
    uint8_t const *key; ///< a pointer to the key
    uint8_t const *nonce; ///< a pointer to the nonce to be used for encryption/decryption
    uint8_t nonce_length; ///< the length of the nonce in bits
} CONTEXT;
    

//The purpose of this function is to implement the logarithm operation.
int logarithm(int a, int b){
	int n=0;
	while(a!=0){
			a=a/b;
			n++;
	}
	return n-1;
}
//The purpose of this function is to implement the exponentiation operation.
int exponent(int a, int b){
	int n=1;
	int i;
	for(i=0;i<b;i++)
		n=n*a;
	return n;
}
//The purpose of this function is to implement the multiplication operation in the GF(2^8).
uint8_t multiply(int val1, int val){
	int result;
	int input_vector[8];
	input_vector[7]=val/exponent(2,7);
	input_vector[6]=(val-input_vector[7]*exponent(2,7))/exponent(2,6);
	input_vector[5]=(val-input_vector[7]*exponent(2,7)-input_vector[6]*exponent(2,6))/exponent(2,5);
	input_vector[4]=(val-input_vector[7]*exponent(2,7)-input_vector[6]*exponent(2,6)-input_vector[5]*exponent(2,5))/exponent(2,4);
	input_vector[3]=(val-input_vector[7]*exponent(2,7)-input_vector[6]*exponent(2,6)-input_vector[5]*exponent(2,5)-input_vector[4]*exponent(2,4))/exponent(2,3);
	input_vector[2]=(val-input_vector[7]*exponent(2,7)-input_vector[6]*exponent(2,6)-input_vector[5]*exponent(2,5)-input_vector[4]*exponent(2,4)-input_vector[3]*exponent(2,3))/exponent(2,2);
	input_vector[1]=(val-input_vector[7]*exponent(2,7)-input_vector[6]*exponent(2,6)-input_vector[5]*exponent(2,5)-input_vector[4]*exponent(2,4)-input_vector[3]*exponent(2,3)-input_vector[2]*exponent(2,2))/exponent(2,1);
	input_vector[0]=(val-input_vector[7]*exponent(2,7)-input_vector[6]*exponent(2,6)-input_vector[5]*exponent(2,5)-input_vector[4]*exponent(2,4)-input_vector[3]*exponent(2,3)-input_vector[2]*exponent(2,2)-input_vector[1]*exponent(2,1))/exponent(2,0);
	result=(val1*exponent(2,7)*input_vector[7])^(val1*exponent(2,6)*input_vector[6])^(val1*exponent(2,5)*input_vector[5])^(val1*exponent(2,4)*input_vector[4])^(val1*exponent(2,3)*input_vector[3])^(val1*exponent(2,2)*input_vector[2])^(val1*exponent(2,1)*input_vector[1])^(val1*exponent(2,0)*input_vector[0]);
	int degree = logarithm(result,2);
	while(degree>=8){
		result=result^(283*exponent(2,degree-8));
		degree=logarithm(result,2);
	}
	return result;
}

/*uint8_t multiply(uint8_t const val, int n){
	int i;
	i = val * 2;
	if(n==2){
		if(i<256)
			return i;
		else
			return i ^ 283;
	}
	else if(n==3){
		if(i<256)
			return i ^ val;
		else
			return (i ^ 283) ^ val;
	}
	else
		return 0;
}*/

//The purpose of this function is to implement the theta linear transformation.
void theta(uint8_t const *val, uint8_t *res){
	res[0]  = multiply(val[0],3) ^  multiply(val[1],2)  ^  multiply(val[2],2);
	res[1]  = multiply(val[0],2) ^  multiply(val[1],3)  ^  multiply(val[2],2);
	res[2]  = multiply(val[0],2) ^  multiply(val[1],2)  ^  multiply(val[2],3);
	res[3]  = multiply(val[3],3) ^  multiply(val[4],2)  ^  multiply(val[5],2);
	res[4]  = multiply(val[3],2) ^  multiply(val[4],3)  ^  multiply(val[5],2);
	res[5]  = multiply(val[3],2) ^  multiply(val[4],2)  ^  multiply(val[5],3);
	res[6]  = multiply(val[6],3) ^  multiply(val[7],2)  ^  multiply(val[8],2);
	res[7]  = multiply(val[6],2) ^  multiply(val[7],3)  ^  multiply(val[8],2);
	res[8]  = multiply(val[6],2) ^  multiply(val[7],2)  ^  multiply(val[8],3);
	res[9]  = multiply(val[9],3) ^  multiply(val[10],2) ^  multiply(val[11],2);
	res[10] = multiply(val[9],2) ^  multiply(val[10],3) ^  multiply(val[11],2);
	res[11] = multiply(val[9],2) ^  multiply(val[10],2) ^  multiply(val[11],3);
}
//The purpose of this function is to implement the extended Eucledian algorithm to find the inverse of an element.
uint8_t extended_gcd(uint8_t const val){
	int small = val;
	int temp_small = val;
	int large = 283;
	int temp_large = 283;
	int i=0;
	int j;
	int bigger=logarithm(283,2);
	int smaller=logarithm(val,2);
	int n=bigger-smaller+1;
	int bigger_coef[2]={1,0};
	int smaller_coef[2]={0,1};
	int temp_coef[2]={0,0};
	if(val == 0)
		return 0;
	else{
		while(small>1){
			for(j=0;j<n;j++){
				while(bigger-smaller>0){
					temp_small=temp_small*2;
					smaller++;
					i++;
				}
				if(bigger==smaller){
					temp_coef[0]=(exponent(2,i)*smaller_coef[0])^temp_coef[0];
					temp_coef[1]=(exponent(2,i)*smaller_coef[1])^temp_coef[1];
					temp_large = temp_small ^ temp_large;
					temp_small=small;
					bigger=logarithm(temp_large,2);
					smaller=logarithm(small,2);
					i=0;
				}
			}
			temp_coef[0]=temp_coef[0]^bigger_coef[0];
			temp_coef[1]=temp_coef[1]^bigger_coef[1];
			large=small;
			small=temp_large;
			temp_large=large;
			temp_small=small;
			bigger=logarithm(large,2);
			smaller=logarithm(small,2);
			n=bigger-smaller+1;
			bigger_coef[0]=smaller_coef[0];
			bigger_coef[1]=smaller_coef[1];
			smaller_coef[0]=temp_coef[0];
			smaller_coef[1]=temp_coef[1];
			temp_coef[0]=0;
			temp_coef[1]=0;
			i=0;
		}
		return smaller_coef[1];
	}
}
//Generalize the Eucledian Algorithm to an array:
void inverse_elements(uint8_t const *val, uint8_t *res){
	int i;
	for(i=0;i<12;i++)
		res[0]=extended_gcd(val[0]);
}
//Affine mapping for a single byte:
uint8_t affine_mapping_single(uint8_t const val){
	int input_vector[8],output_vector[8];
	input_vector[7]=val/exponent(2,7);
	input_vector[6]=(val-input_vector[7]*exponent(2,7))/exponent(2,6);
	input_vector[5]=(val-input_vector[7]*exponent(2,7)-input_vector[6]*exponent(2,6))/exponent(2,5);
	input_vector[4]=(val-input_vector[7]*exponent(2,7)-input_vector[6]*exponent(2,6)-input_vector[5]*exponent(2,5))/exponent(2,4);
	input_vector[3]=(val-input_vector[7]*exponent(2,7)-input_vector[6]*exponent(2,6)-input_vector[5]*exponent(2,5)-input_vector[4]*exponent(2,4))/exponent(2,3);
	input_vector[2]=(val-input_vector[7]*exponent(2,7)-input_vector[6]*exponent(2,6)-input_vector[5]*exponent(2,5)-input_vector[4]*exponent(2,4)-input_vector[3]*exponent(2,3))/exponent(2,2);
	input_vector[1]=(val-input_vector[7]*exponent(2,7)-input_vector[6]*exponent(2,6)-input_vector[5]*exponent(2,5)-input_vector[4]*exponent(2,4)-input_vector[3]*exponent(2,3)-input_vector[2]*exponent(2,2))/exponent(2,1);
	input_vector[0]=(val-input_vector[7]*exponent(2,7)-input_vector[6]*exponent(2,6)-input_vector[5]*exponent(2,5)-input_vector[4]*exponent(2,4)-input_vector[3]*exponent(2,3)-input_vector[2]*exponent(2,2)-input_vector[1]*exponent(2,1))/exponent(2,0);
	output_vector[7]=input_vector[3]^input_vector[4]^input_vector[5]^input_vector[6]^input_vector[7]^0;
	output_vector[6]=input_vector[2]^input_vector[3]^input_vector[4]^input_vector[5]^input_vector[6]^1;
	output_vector[5]=input_vector[1]^input_vector[2]^input_vector[3]^input_vector[4]^input_vector[5]^1;
	output_vector[4]=input_vector[0]^input_vector[1]^input_vector[2]^input_vector[3]^input_vector[4]^0;
	output_vector[3]=input_vector[7]^input_vector[0]^input_vector[1]^input_vector[2]^input_vector[3]^0;
	output_vector[2]=input_vector[6]^input_vector[7]^input_vector[0]^input_vector[1]^input_vector[2]^0;
	output_vector[1]=input_vector[5]^input_vector[6]^input_vector[7]^input_vector[0]^input_vector[1]^1;
	output_vector[0]=input_vector[4]^input_vector[5]^input_vector[6]^input_vector[7]^input_vector[0]^1;
	return (exponent(2,7)*output_vector[7]+exponent(2,6)*output_vector[6]+exponent(2,5)*output_vector[5]+exponent(2,4)*output_vector[4]+exponent(2,3)*output_vector[3]+exponent(2,2)*output_vector[2]+exponent(2,1)*output_vector[1]+exponent(2,0)*output_vector[0]);
}
//Affine mapping generalized:
void affine_mapping(uint8_t const *val, uint8_t *res){
	int i;
	for(i=0;i<12;i++)
		res[i]=affine_mapping_single(val[i]);
}
//S-Box single:
uint8_t S_box_single(uint8_t const val){
	return affine_mapping_single(extended_gcd(val));
}
//S-Box:
void S_box(uint8_t const *val, uint8_t *res){
	int i;
	for(i=0;i<12;i++){
		res[i]=affine_mapping_single(extended_gcd(val[i]));
	}
}
//The byte permutation:
void Permutation(uint8_t const *val, uint8_t *res){
	res[0]=val[0];
	res[1]=val[10];
	res[2]=val[8];
	res[3]=val[3];
	res[4]=val[1];
	res[5]=val[11];
	res[6]=val[6];
	res[7]=val[4];
	res[8]=val[2];
	res[9]=val[9];
	res[10]=val[7];
	res[11]=val[5];
}
//The purpose of this function is to implement the inverse theta linear transformation:
void theta_inverse(uint8_t const *val, uint8_t *res){
	res[0]  = multiply(val[0],246) ^  multiply(val[1],247)  ^  multiply(val[2],247);
	res[1]  = multiply(val[0],247) ^  multiply(val[1],246)  ^  multiply(val[2],247);
	res[2]  = multiply(val[0],247) ^  multiply(val[1],247)  ^  multiply(val[2],246);
	res[3]  = multiply(val[3],246) ^  multiply(val[4],247)  ^  multiply(val[5],247);
	res[4]  = multiply(val[3],247) ^  multiply(val[4],246)  ^  multiply(val[5],247);
	res[5]  = multiply(val[3],247) ^  multiply(val[4],247)  ^  multiply(val[5],246);
	res[6]  = multiply(val[6],246) ^  multiply(val[7],247)  ^  multiply(val[8],247);
	res[7]  = multiply(val[6],247) ^  multiply(val[7],246)  ^  multiply(val[8],247);
	res[8]  = multiply(val[6],247) ^  multiply(val[7],247)  ^  multiply(val[8],246);
	res[9]  = multiply(val[9],246) ^  multiply(val[10],247) ^  multiply(val[11],247);
	res[10] = multiply(val[9],247) ^  multiply(val[10],246) ^  multiply(val[11],247);
	res[11] = multiply(val[9],247) ^  multiply(val[10],247) ^  multiply(val[11],246);
}
void round_key_evolution(uint8_t const *val,uint8_t *res,int t){
	res[0]=val[0]^S_box_single(val[10])^multiply(1,exponent(2,t));
	res[1]=val[1]^S_box_single(val[11]);
	res[2]=val[2]^S_box_single(val[9]);
	
	res[3]=val[3]^res[0];
	res[4]=val[4]^res[1];
	res[5]=val[5]^res[2];
	
	res[6]=val[6]^res[3];
	res[7]=val[7]^res[4];
	res[8]=val[8]^res[5];
	
	res[9]=val[9]^res[6];
	res[10]=val[10]^res[7];
	res[11]=val[11]^res[8];
}
void complete_round(uint8_t const *plain,uint8_t const *round_key,uint8_t *res){
	uint8_t temp[12];
	int i;
	theta(plain,res);
	S_box(res,temp);
	Permutation(temp,res);
	for(i=0;i<12;i++)
		res[i]=res[i]^round_key[i];
}
//The purpose of this function is to implement the counter operation:
void counter(uint8_t nonce_counter[12]){
	if(nonce_counter[11]<255)
			nonce_counter[11]+=1;
		else{
			nonce_counter[11]=0;
			if(nonce_counter[10]<255)
				nonce_counter[10]+=1;
			else{
				nonce_counter[10]=0;
				if(nonce_counter[9]<255)
					nonce_counter[9]+=1;
				else{
					nonce_counter[9]=0;
					if(nonce_counter[8]<255)
						nonce_counter[8]+=1;
					else{
						nonce_counter[8]=0;
						if(nonce_counter[7]<255)
							nonce_counter[7]+=1;
						else{
							nonce_counter[7]=0;
							if(nonce_counter[6]<255)
								nonce_counter[6]+=1;
							else{
								nonce_counter[6]=0;
							}
						}
					}
				}
			}
		}
}
    


/** The |bksq_encrypt| ist the main method to encrypt a single block of data with the BKSQ algorithm. 
 * Note that we only support 96 bit (12 byte) keys.
 * 
 * @param plain points to a 96 bit (12 byte) input-to-be-encrypted
 * @param cyphertext points to a 96 bit (12 byte) array to receive the output
 * @param key provides the 96 bit (12 byte) key for encryption
 * @returns whether operation was successful
 */
uint8_t bksq_encrypt(uint8_t const * plain, uint8_t * cyphertext, uint8_t const * key) {

    // TODO: put your code for BKSQ-Encryption here.
    
    uint8_t temp[12];
    uint8_t temp1_key[12];
    uint8_t temp2_key[12];
    //Theta inverse linear transformation:
    theta_inverse(plain,temp);
    int i;
    //Key whitening (0th round):
    for(i=0;i<12;i++)
    	temp[i]=temp[i]^key[i];
    //1st round key evolution and round:	
    round_key_evolution(key,temp1_key,1);
    complete_round(temp,temp1_key,cyphertext);
    //2nd round key evolution and round:
    round_key_evolution(temp1_key,temp2_key,2);
    complete_round(cyphertext,temp2_key,temp);
    //3rd round key evolution and round:
    round_key_evolution(temp2_key,temp1_key,3);
    complete_round(temp,temp1_key,cyphertext);
    //4th round key evolution and round:
    round_key_evolution(temp1_key,temp2_key,4);
    complete_round(cyphertext,temp2_key,temp);
    //5th round key evolution and round:
    round_key_evolution(temp2_key,temp1_key,5);
    complete_round(temp,temp1_key,cyphertext);
    //6th round key evolution and round:
    round_key_evolution(temp1_key,temp2_key,6);
    complete_round(cyphertext,temp2_key,temp);
    //7th round key evolution and round:
    round_key_evolution(temp2_key,temp1_key,7);
    complete_round(temp,temp1_key,cyphertext);
    //8th round key evolution and round:
    round_key_evolution(temp1_key,temp2_key,8);
    complete_round(cyphertext,temp2_key,temp);
    //9th round key evolution and round:
    round_key_evolution(temp2_key,temp1_key,9);
    complete_round(temp,temp1_key,cyphertext);
    //10th round key evolution and round:
    round_key_evolution(temp1_key,temp2_key,10);
    complete_round(cyphertext,temp2_key,temp);
    //Updating the cyphertext array:
    for(i=0;i<12;i++)
    	cyphertext[i]=temp[i];
    

    return BKSQ_ENCRYPT_OK;
}


   



/**
 * Encrypts/Decrypts data in counter mode. The structure |ctx| holds the relevant data.
 * Note that operation happens \e in place, so input data is overwritten by output!
 * @param ctx The encryption/decryption context.
 * @return Returns 0, if encryption/decryption was successful
 */
uint8_t ctr(CONTEXT const ctx) {
    // sanity checks
    if ((ctx.data_length % BLOCKSIZE) != 0) return INVALID_DATA_LENGTH;
    if (ctx.nonce_length != (BLOCKSIZE / 2)) return INVALID_NONCE_LENGTH;
    
    
    /*typedef struct {
    uint8_t *data; ///< a pointer to the input data
    uint32_t data_length; ///< length of the input data in bits; must be a multiple of the blocklength
    uint8_t const *key; ///< a pointer to the key
    uint8_t const *nonce; ///< a pointer to the nonce to be used for encryption/decryption
    uint8_t nonce_length; ///< the length of the nonce in bits
} CONTEXT;*/

    // TODO: put your code for Counter-Mode here
    int n=ctx.data_length/(8*12);
    int i;
    int j;
    uint8_t temp1[12];
    uint8_t temp2[12];
    uint8_t nonce_counter[12];
    for(i=0;i<6;i++)
    	nonce_counter[i]=ctx.nonce[i];
    for(i=6;i<12;i++)
    	nonce_counter[i]=0;
    for(i=0;i<n;i++){
    	for(j=0;j<12;j++){
    		temp1[j]=ctx.data[12*i+j];
		}
		bksq_encrypt(nonce_counter,temp2,ctx.key);
		for(j=0;j<12;j++){
			ctx.data[12*i+j]=temp2[j]^temp1[j];
		}
		counter(nonce_counter);
	}
	
    return CTR_OK;
}

/**
 * hashes given data using the Davies-Meyer-construction
 * @param data a pointer to the data to be hashed
 * @param data_length The length of the data in bits
 * @param hash a pointer to an array for receiving the hash, must be of size |BLOCKSIZE_BYTE| bytes
 * @return Returns 0, if hashing successful
 */
uint8_t dmhash(uint8_t const *data, uint32_t const data_length, uint8_t * hash) {
    // sanity checks
    if ((data_length % BLOCKSIZE) != 0) return INVALID_DATA_LENGTH;
    
	// TODO: put your code for hashing here
	int n=data_length/(8*12);
	int i;
	int j;
	uint8_t temp_key[12];
	uint8_t temp_cipher[12];
	//Initializing H0 as full of zeros:
	for(i=0;i<12;i++)
		hash[i]=0;
	for(i=0;i<n;i++){
		//Storing the key number i, i.e. the plaintext xi in a temporary variable:
		for(j=0;j<12;j++){
    		temp_key[j]=data[12*i+j];
		}
		//Storing the output in a temporary variable temp_cipher:
		bksq_encrypt(hash,temp_cipher,temp_key);
		//Basic bitwise XOR operation:
		for(j=0;j<12;j++){
			hash[j]=hash[j]^temp_cipher[j];
		}
	}

    return DM_OK;
}

/**
 * computes a HMAC as in RFC 2104 using the dmhash function
 * @param data a pointer to the data to be hashed
 * @param data_length the length of the data in bits
 * @param key the key to be used for computing HMAC
 * @param tag a pointer to an array for receiving the MAC, must be of size |BLOCKSIZE_BYTE| bytes
 * @param data_prefix either NULL or a pointer to a single block which is prepended to data
 * @return Returns 0, if MACing successful
 */
uint8_t hmac(uint8_t const *data, uint32_t const data_length, uint8_t const *key, uint32_t const key_length, uint8_t * tag, uint8_t * data_prefix, uint32_t const data_prefix_length) {
    
	// TODO: put your code for MACing here
	
	if (key_length != BLOCKSIZE) return INVALID_KEY_LENGTH; //Checking whether the key is of appropriate size.
	
	int n;
	if(data_length>data_prefix_length)
		n=data_length/8+12;
	else
		n=data_prefix_length/8+12;
		
	uint8_t first_input[n];
	
	int i;
	
	if(data_prefix==NULL){
		n=data_length/8;
		for(i=12;i<n+12;i++)
			first_input[i]=data[i-12];
	}
	else{
		n=data_prefix_length/8;
		for(i=12;i<n+12;i++)
			first_input[i]=data_prefix[i-12];
	}
	
	uint8_t second_input[24];
	uint8_t ipad[12];
	uint8_t opad[12];
	uint8_t temp[12];
	for(i=0;i<12;i++){
		ipad[i]=54;
		opad[i]=92;
	}
	for(i=0;i<12;i++)
		first_input[i]=ipad[i]^key[i];
	dmhash(first_input,8*n+12*8,temp);
	for(i=0;i<12;i++)
		second_input[i]=opad[i]^key[i];
	for(i=12;i<24;i++)
		second_input[i]=temp[i-12];
	dmhash(second_input,24*8,tag);	
    return HMAC_OK;
}

/**
 * Encrypts data in an authenticated encryption mode, namely Encrypt-then-MAC (EtM)
 * with Counter-Mode Encryption and HMAC
 * The structure |ctx| holds the relevant data.
 * Note that operation happens *in place*, so input data is overwritten by output!
 * @param ctx The encryption context as with ctr()
 * @param tag a buffer to receive the authentication tag
 * @return Returns 0, if encryption/decryption was successful
 */
uint8_t ae_enc(CONTEXT const ctx, uint8_t *tag) {

    // TODO: put your code for EtM here
	ctr(ctx);
	int n=ctx.data_length/8+12;
	uint8_t temp[n];
	int i;
	uint8_t nonce_counter[12];
    for(i=0;i<6;i++)
    	nonce_counter[i]=ctx.nonce[i];
    for(i=6;i<12;i++)
    	nonce_counter[i]=0;
    for(i=0;i<12;i++)
    	temp[i]=nonce_counter[i];
    for(i=12;i<n;i++)
    	temp[i]=ctx.data[i-12];
    hmac(ctx.data,ctx.data_length,ctx.key,12*8,tag,temp,n*8);
    return CTR_OK | HMAC_OK; 
}
