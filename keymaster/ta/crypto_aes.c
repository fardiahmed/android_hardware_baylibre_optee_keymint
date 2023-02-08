/*
 *
 * Copyright (C) 2017 GlobalLogic
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "crypto_aes.h"

static bool TA_is_stream_cipher(const keymaster_block_mode_t mode)
{
	switch (mode) {
	case KM_MODE_CBC:
	case KM_MODE_ECB:
		return false;
	default:/*KM_MODE_GCM, KM_MODE_CTR*/
		return true;
	}
}

static void TA_append_tag(keymaster_blob_t *output, uint32_t *out_size,
			  const uint8_t *tag, const uint32_t tag_len)
{
	/* is assumed that output has enough allocated memory */
	TEE_MemMove(output->data + *out_size, tag, tag_len);
	*out_size += tag_len;
}

static keymaster_error_t TA_append_input(keymaster_blob_t *input,
					 keymaster_operation_t *operation,
					 const uint32_t to_copy)
{
	uint8_t *data = NULL;
	uint32_t tag_length = operation->mac_length / 8;
	uint32_t push_to_input = operation->a_data_length + to_copy - tag_length;

	data = TEE_Malloc(input->data_length + push_to_input, TEE_MALLOC_FILL_ZERO);
	if (!data) {
		EMSG("Failed to allocate memory for input appended by TAG");
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}
	TEE_MemMove(data, operation->a_data, push_to_input);
	TEE_MemMove(data + push_to_input, input->data, input->data_length);
	TEE_Free(input->data);

	input->data = data;
	input->data_length += push_to_input;
	operation->a_data_length -= push_to_input;
	TEE_MemMove(operation->a_data, operation->a_data + push_to_input,
		    operation->a_data_length);
	return KM_ERROR_OK;
}

static keymaster_error_t TA_save_gcm_tag(keymaster_blob_t *input,
					 keymaster_operation_t *operation)
{
	keymaster_error_t res = KM_ERROR_OK;
	uint32_t tag_size = operation->mac_length / 8;
	uint32_t to_copy = tag_size;

	if (input->data_length == 0)
		return res;
	if (input->data_length < tag_size)
		to_copy = input->data_length;
	if (operation->a_data_length + to_copy > tag_size) {
		res = TA_append_input(input, operation, to_copy);
		if (res != KM_ERROR_OK)
			return res;
	}

	TEE_MemMove(operation->a_data + operation->a_data_length, input->data +
		    (input->data_length - to_copy), to_copy);
	input->data_length -= to_copy;
	operation->a_data_length += to_copy;
	DMSG("Tag has been stored with size %u", operation->a_data_length);
	return res;
}

static keymaster_error_t TA_aes_gcm_prepare(keymaster_operation_t *operation,
					    const keymaster_key_param_set_t *in_params,
					    keymaster_blob_t *input)
{
	for (uint32_t i = 0; i < in_params->length; i++) {
		if (in_params->params[i].tag == KM_TAG_ASSOCIATED_DATA) {
			if (operation->got_input) {
				EMSG("KM_TAG_ASSOCIATED_DATA is found when input data has been received already");
				return KM_ERROR_INVALID_TAG;
			}
			TEE_AEUpdateAAD(*operation->operation,
					in_params->params[i].key_param.blob.data,
					in_params->params[i].key_param.blob.data_length);
			break;
		}
	}
	if (input->data_length != 0)
		operation->got_input = true;

	/* During AES GCM decryption, the last KM_TAG_MAC_LENGTH bytes
	 * of the data provided to the last update call is the tag
	 */
	if (operation->mac_length != UNDEFINED &&
	    operation->purpose == KM_PURPOSE_DECRYPT &&
	    input->data_length > 0) {
		if (operation->a_data == NULL) {
			/* Freed when operation is
			 * aborted (TA_abort_operation)
			 */
			operation->a_data = TEE_Malloc(operation->mac_length/8,
						       TEE_MALLOC_FILL_ZERO);
			if (!operation->a_data) {
				EMSG("Failed to allocate memory for authentication tag");
				return KM_ERROR_MEMORY_ALLOCATION_FAILED;
			}
		}
		/* Since a given invocation of update cannot know if
		 * it's the last invocation, it must process all but
		 * the tag length and buffer the possible tag data
		 * for processing during finish.
		 */
		return TA_save_gcm_tag(input, operation);
	}
	return KM_ERROR_OK;
}

static void TA_fill_input_op(keymaster_operation_t *operation, keymaster_blob_t *input,
			     keymaster_blob_t *input_op)
{
	/* KM_MODE_CBC, KM_MODE_ECB */
	if (!TA_is_stream_cipher(operation->mode)) {
		/* prepend input_op if remaining input_saved data present */
		input_op->data_length = input->data_length + operation->input_saved.data_length;
		input_op->data = TEE_Malloc(input_op->data_length, TEE_MALLOC_FILL_ZERO);

		if (operation->input_saved.data)
			memcpy(input_op->data, operation->input_saved.data,
			       operation->input_saved.data_length);
		if (input->data)
			memcpy(input_op->data + operation->input_saved.data_length, input->data,
			       input->data_length);

		if (operation->input_saved.data)
			TEE_Free(operation->input_saved.data);
		operation->input_saved.data = NULL;
		operation->input_saved.data_length = 0;
	} else {
		input_op->data_length = input->data_length;
		input_op->data = TEE_Malloc(input_op->data_length, TEE_MALLOC_FILL_ZERO);
		if (input->data)
			memcpy(input_op->data, input->data, input->data_length);
	}
}

static void TA_pkcs7_prepend_output(keymaster_operation_t *operation, keymaster_blob_t *output)
{
	uint8_t* tmp = TEE_Malloc(output->data_length, TEE_MALLOC_FILL_ZERO);
	memcpy(tmp, output->data, output->data_length);

	output->data = TEE_Realloc(output->data, output->data_length +
				   operation->output_saved.data_length);

	memcpy(output->data, operation->output_saved.data,
	       operation->output_saved.data_length);
	memcpy(output->data + operation->output_saved.data_length,
	       tmp, output->data_length);

	output->data_length += operation->output_saved.data_length;

	TEE_Free(tmp);
}

static void TA_pkcs7_save_output(keymaster_operation_t *operation, keymaster_blob_t *output,
                                 bool remaining_input)
{
	uint8_t* tmp = NULL;
	size_t tmp_length = 0, save_offset = 0;

        /* If some output data have been saved from previous operation,
         * add these data to tmp buffer.
         */
	if (operation->output_saved.data) {
		tmp_length = operation->output_saved.data_length;
		tmp = TEE_Malloc(tmp_length, TEE_MALLOC_FILL_ZERO);
		memcpy(tmp, operation->output_saved.data, tmp_length);

		TEE_Free(operation->output_saved.data);
		operation->output_saved.data = NULL;
		operation->output_saved.data_length = 0;
	}

	if (output->data_length > 0 && (output->data_length % BLOCK_SIZE == 0)) {

                /* If we have remaining input, that means we can produce the output.
                 * Otherwise we should save the last block of output and wait next operation.
                 */
                if (remaining_input == false) {
                        save_offset = ((output->data_length / BLOCK_SIZE) - 1) * BLOCK_SIZE;

                        /* save last block of output */
                        operation->output_saved.data_length = BLOCK_SIZE;
                        operation->output_saved.data = TEE_Malloc(BLOCK_SIZE, TEE_MALLOC_FILL_ZERO);
                        memcpy(operation->output_saved.data, output->data + save_offset, BLOCK_SIZE);

                        /* append to tmp the whole output without last block */
                        if (save_offset > 0) {
                                if (tmp)
                                        tmp = TEE_Realloc(tmp, tmp_length + save_offset);
                                else
                                        tmp = TEE_Malloc(save_offset, TEE_MALLOC_FILL_ZERO);
                                memcpy(tmp + tmp_length, output->data, save_offset);
                                tmp_length += save_offset;
                        }
                } else {
                        if (tmp)
                                tmp = TEE_Realloc(tmp, tmp_length + output->data_length);
                        else
                                tmp = TEE_Malloc(output->data_length, TEE_MALLOC_FILL_ZERO);
                        memcpy(tmp + tmp_length, output->data, output->data_length);
                        tmp_length += output->data_length;
                }

                TEE_Free(output->data);
        }

	if (tmp) {
		output->data = TEE_Malloc(tmp_length, TEE_MALLOC_FILL_ZERO);
		memcpy(output->data, tmp, tmp_length);
		output->data_length = tmp_length;
		TEE_Free(tmp);
	} else {
		output->data = NULL;
		output->data_length = 0;
	}
}

keymaster_error_t TA_aes_finish(keymaster_operation_t *operation,
				keymaster_blob_t *input,
				keymaster_blob_t *output, uint32_t *out_size,
				uint32_t tag_len,
				const keymaster_key_param_set_t *in_params)
{
	TEE_Result tee_res = TEE_SUCCESS;
	keymaster_error_t res = KM_ERROR_OK;
	uint8_t *tag = NULL;
	keymaster_blob_t input_op = EMPTY_BLOB;

	TA_fill_input_op(operation, input, &input_op);

	if (operation->padding == KM_PAD_PKCS7 && operation->purpose == KM_PURPOSE_ENCRYPT) {
		res = TA_add_pkcs7_pad(&input_op, true, output, out_size);
		if (res != KM_ERROR_OK)
			goto out;
	} else if (operation->padding == KM_PAD_NONE &&
		   (operation->mode == KM_MODE_CBC || operation->mode == KM_MODE_ECB) &&
		   input_op.data_length % BLOCK_SIZE != 0) {
		EMSG("Input data size for AES CBC and ECB modes without padding must be a multiple of block size");
		res = KM_ERROR_INVALID_INPUT_LENGTH;
		goto out;
	} else if (operation->padding == KM_PAD_PKCS7 &&
		   operation->purpose == KM_PURPOSE_DECRYPT &&
		   input_op.data_length % BLOCK_SIZE != 0) {
		EMSG("Input data size for AES PKCS7 must be a multiple of block size");
		res = KM_ERROR_INVALID_INPUT_LENGTH;
		goto out;
	}

	if (operation->mode == KM_MODE_GCM) {
		/* For KM_MODE_GCM */
		res = TA_aes_gcm_prepare(operation, in_params, &input_op);
		if (res != KM_ERROR_OK)
			goto out;
		if (operation->purpose == KM_PURPOSE_ENCRYPT) {
			/* During encryption */
			tag = TEE_Malloc(tag_len, TEE_MALLOC_FILL_ZERO);
			if (!tag) {
				EMSG("Failed to allocate memory for GCM tag");
				res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
				goto out;
			}
			res = TEE_AEEncryptFinal(*operation->operation,
						 input_op.data, input_op.data_length,
						 output->data, out_size,
						 tag, &tag_len);
			if (res != KM_ERROR_OK) {
				EMSG("TEE_AEEncryptFinal failed, res=%x", res);
				goto out;
			}
			/* after processing all plaintext, compute the
			 * tag (KM_TAG_MAC_LENGTH bytes) and append it
			 * to the returned ciphertext
			 */
			TA_append_tag(output, out_size, tag, tag_len);
		} else {/* KM_PURPOSE_DECRYPT	During decryption
			 * process the last KM_TAG_MAC_LENGTH bytes from
			 * input data of last Update as the tag
			 */
			tee_res = TEE_AEDecryptFinal(*operation->operation,
						     input_op.data, input_op.data_length,
						     output->data, out_size,
						     operation->a_data, /*tag to compare*/
						     operation->mac_length / 8);
			if (tee_res == TEE_ERROR_MAC_INVALID) {
				/* tag verification fails */
				EMSG("AES GCM verification failed, res=%x", res);
				res = KM_ERROR_VERIFICATION_FAILED;
				goto out;
			}
		}
	} else {
		res = TEE_CipherDoFinal(*operation->operation, input_op.data,
					input_op.data_length, output->data,
					out_size);
	}

	output->data_length = *out_size;

	if (res == KM_ERROR_OK && operation->padding == KM_PAD_PKCS7 &&
	    operation->purpose == KM_PURPOSE_DECRYPT) {

		/* prepend output if remaining output_saved data present */
		if (operation->output_saved.data) {
			TA_pkcs7_prepend_output(operation, output);
			*out_size = output->data_length;

			TEE_Free(operation->output_saved.data);
			operation->output_saved.data = NULL;
			operation->output_saved.data_length = 0;
		}

		if (TA_check_pkcs7_pad(output))
			res = TA_remove_pkcs7_pad(output, out_size);
		else
			res = KM_ERROR_INVALID_ARGUMENT;
	}
out:
	if (input_op.data)
		TEE_Free(input_op.data);
	if (tag)
		TEE_Free(tag);
	return res;
}

keymaster_error_t TA_aes_update(keymaster_operation_t *operation,
				keymaster_blob_t *input,
				keymaster_blob_t *output,
				uint32_t *out_size,
				const uint32_t input_provided,
				size_t *input_consumed,
				const keymaster_key_param_set_t *in_params)
{
	keymaster_error_t res = KM_ERROR_OK;
	uint32_t pos = 0U;
	uint32_t remainder = 0;
	uint32_t in_size = BLOCK_SIZE;
	keymaster_blob_t input_op = EMPTY_BLOB;
	size_t remaining_input = 0;

	TA_fill_input_op(operation, input, &input_op);

	/* save in input_saved if input_op size is not modulo block size */
	if (!TA_is_stream_cipher(operation->mode)) {
		remaining_input = input_op.data_length % BLOCK_SIZE;
		if (remaining_input) {
			input_op.data_length -= remaining_input;
			operation->input_saved.data_length = remaining_input;
			operation->input_saved.data = TEE_Malloc(remaining_input,
								 TEE_MALLOC_FILL_ZERO);
			memcpy(operation->input_saved.data, input_op.data + input_op.data_length,
			       remaining_input);
		}
	}

	if (operation->mode == KM_MODE_GCM) {
		/* check presence of associated data for AES keys */
		res = TA_aes_gcm_prepare(operation, in_params, &input_op);
		if (res != KM_ERROR_OK)
			goto out;
		/* Resize output if input_op length increased */
		res = TA_check_out_size(input_op.data_length, output, out_size,
					operation->mac_length / 8);
		if (res != KM_ERROR_OK)
			goto out;
		res = TEE_AEUpdate(*operation->operation, input_op.data,
				   input_op.data_length, output->data, out_size);
		if (res != KM_ERROR_OK)
			goto out;
		output->data_length += *out_size;
		*input_consumed = input_provided;
	} else {
		if (operation->mode == KM_MODE_CTR)
			/* CTR is a stream mode */
			in_size = input_op.data_length;

		remainder = input_op.data_length;
		while (operation->mode == KM_MODE_CTR || remainder / BLOCK_SIZE != 0) {
			/* calculate memory left.
			 * Add BLOCK_SIZE in case adding padding
			 */
			*out_size = BLOCK_SIZE + input_op.data_length - output->data_length;
			res = TEE_CipherUpdate(*operation->operation,
					       input_op.data + pos, in_size,
					       output->data + pos, out_size);
			if (res != TEE_SUCCESS) {
				EMSG("Error TEE_CipherUpdate, res=%x", res);
				goto out;
			}
			output->data_length += *out_size;
			pos += in_size;
			*input_consumed += in_size;
			remainder -= in_size;
			if (remainder < BLOCK_SIZE)
				break;
		}
	}

	*input_consumed += remaining_input;
	if (*input_consumed > input_provided)
		*input_consumed = input_provided;

	if (res == KM_ERROR_OK && operation->padding == KM_PAD_PKCS7 &&
	    operation->purpose == KM_PURPOSE_DECRYPT) {

		/* When padding is used, output is produced one input byte later:
		 * once the first byte of the next input block is provided.
		 */
		TA_pkcs7_save_output(operation, output, remaining_input > 0);
		*out_size = output->data_length;
	}

	if (input_op.data)
		TEE_Free(input_op.data);
out:
	return res;
}

/*
 * Initialize the `TEE_OperationHandle` for the given algorithm, mode,
 * objecttype, objectusage, attributeid, key and iv.  If returns
 * KM_ERROR_OK, the operation will be properly initialized (and should be
 * freed with TEE_FreeOperation).
 */
keymaster_error_t TA_aes_init_operation(uint32_t algorithm, uint32_t mode,
					uint32_t objecttype, uint32_t objectusage,
					uint32_t attributeid,
					void *keybuffer, uint32_t maxkeylen,
					void *iv, size_t ivlen,
					TEE_OperationHandle *op)
{
	TEE_Result result;
	keymaster_error_t res = KM_ERROR_INVALID_ARGUMENT;
	TEE_ObjectHandle trans_key;
	TEE_Attribute attrs;

	if (!keybuffer || !op)
		goto out;

	result = TEE_AllocateOperation(op, algorithm, mode, (maxkeylen * 8));
	if (result != TEE_SUCCESS) {
		EMSG("can not allocate operation (0x%x)", result);
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto out;
	}

	result = TEE_AllocateTransientObject(objecttype, (maxkeylen * 8), &trans_key);
	if (result != TEE_SUCCESS) {
		EMSG("can not allocate transient object 0x%x", result);
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto out1;
	}
	TEE_RestrictObjectUsage(trans_key, objectusage);

	TEE_InitRefAttribute(&attrs, attributeid, keybuffer, maxkeylen);
	result = TEE_PopulateTransientObject(trans_key, &attrs, 1);
	if (result != TEE_SUCCESS) {
		EMSG("populate transient object error");
		res = KM_ERROR_INVALID_ARGUMENT;
		goto out2;
	}
	result = TEE_SetOperationKey(*op, trans_key);
	if (result != TEE_SUCCESS) {
		EMSG("can not set operation key");
		res = KM_ERROR_INVALID_ARGUMENT;
		goto out2;
	}

	TEE_FreeTransientObject(trans_key);

	TEE_CipherInit(*op, iv, ivlen);

	return KM_ERROR_OK;

out2:
	TEE_FreeTransientObject(trans_key);
out1:
	TEE_FreeOperation(*op);
out:
	return res;
}
