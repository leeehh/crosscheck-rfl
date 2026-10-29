// SPDX-License-Identifier: GPL-2.0

#include <sound/pcm.h>
#include <sound/pcm-indirect.h>

/* `snd_pcm_indirect_*` (playback/capture transfer/pointer) are static inlines — wrap them so a
 * Rust driver can call them (the indirect hw_ptr math for a vq-based PCM driver). */
int rust_helper_snd_pcm_indirect_playback_transfer(struct snd_pcm_substream *substream,
						    struct snd_pcm_indirect *rec,
						    snd_pcm_indirect_copy_t copy)
{
	return snd_pcm_indirect_playback_transfer(substream, rec, copy);
}

snd_pcm_uframes_t rust_helper_snd_pcm_indirect_playback_pointer(struct snd_pcm_substream *substream,
								struct snd_pcm_indirect *rec,
								unsigned int ptr)
{
	return snd_pcm_indirect_playback_pointer(substream, rec, ptr);
}

int rust_helper_snd_pcm_indirect_capture_transfer(struct snd_pcm_substream *substream,
						   struct snd_pcm_indirect *rec,
						   snd_pcm_indirect_copy_t copy)
{
	return snd_pcm_indirect_capture_transfer(substream, rec, copy);
}

snd_pcm_uframes_t rust_helper_snd_pcm_indirect_capture_pointer(struct snd_pcm_substream *substream,
							       struct snd_pcm_indirect *rec,
							       unsigned int ptr)
{
	return snd_pcm_indirect_capture_pointer(substream, rec, ptr);
}
