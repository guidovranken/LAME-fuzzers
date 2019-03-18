/* LAME encoder fuzzer by Guido Vranken <guidovranken@gmail.com> */

#include <fuzzing/datasource/datasource.hpp>
#include <stdexcept>
#include <string>
#include <stdint.h>
#include <stdlib.h>
#include <lame.h>

using fuzzing::datasource::Datasource;

class Limit {
    private:
        const size_t min;
        const size_t max;
    public:
        Limit(const size_t min, const size_t max) :
            min(min), max(max) { }
        size_t Test(const size_t val) const {
            if ( val < min || val > max ) {
                throw std::runtime_error("Value not within bounds");
            }

            return val;
        }

        size_t Generate(fuzzing::datasource::Datasource& ds) {
            const size_t ret = ds.Get<uint32_t>();
            return Test(ret);
        }
};

namespace limits {
    static Limit OutBufferSize(1, 1024*1024);
    static Limit MinBitrate(1, 1024);
    static Limit MaxBitrate(1, 1024);
    static Limit ABRBitrate(1, 1024);
    static Limit CBRBitrate(1, 1024);
    static Limit OutSamplerate(100, 1000000);
    static Limit Quality(100, 1000000);
}

template <bool Debug>
class EncoderFuzzer {
    private:
        Datasource& ds;
        lame_global_flags* flags = nullptr;
        uint8_t* outBuffer = nullptr;
        const size_t outBufferSize;
        
        void setBitrateModeVBR_RH(void) {
            lame_set_VBR(flags, vbr_rh);
            Debug ? printf("VBR = vbr_rh\n") : 0;
        }

        void setBitrateModeVBR_MTRH(void) {
            lame_set_VBR(flags, vbr_mtrh);
            Debug ? printf("VBR = vbr_mtrh\n") : 0;
        }

        void setBitrateModeVBR_ABR(void) {
            lame_set_VBR(flags, vbr_abr);
            Debug ? printf("VBR = vbr_abr\n") : 0;

            const size_t ABRBitrate = limits::ABRBitrate.Generate(ds);
            lame_set_VBR_mean_bitrate_kbps(flags, ABRBitrate);
            Debug ? printf("ABR bitrate = %zu\n", ABRBitrate) : 0;
        }

        size_t setMinBitrate(void) {
            if ( ds.Get<bool>() ) return 0;

            const size_t minBitrate = limits::MinBitrate.Generate(ds);
            Debug ? printf("VBR = min bitrate = %zu\n", minBitrate) : 0;

            return minBitrate;
        }

        void setMaxBitrate(const size_t minBitrate) {
            if ( ds.Get<bool>() ) return;

            const size_t maxBitrate = limits::MaxBitrate.Generate(ds);
            if ( minBitrate > maxBitrate ) {
                throw std::runtime_error("minBitrate > maxBitrate");
            }
            lame_set_VBR_max_bitrate_kbps(flags, maxBitrate);
            Debug ? printf("VBR = max bitrate = %zu\n", maxBitrate) : 0;
        }

        void setBitrateModeVBR(void) {
            const uint8_t whichVbr = ds.Get<uint8_t>() % 3;
            if ( whichVbr == 0 ) {
                setBitrateModeVBR_RH();
            } else if ( whichVbr == 1 ) {
                setBitrateModeVBR_MTRH();
            } else if ( whichVbr == 2 ) {
                setBitrateModeVBR_ABR();
            }

            size_t minBitrate = setMinBitrate();
            setMaxBitrate(minBitrate);
        }
        
        void setBitrateModeCBR(void) {
            lame_set_VBR(flags, vbr_off);
            Debug ? printf("VBR = vbr_off\n") : 0;

            const size_t bitrate = limits::CBRBitrate.Generate(ds);

            lame_set_brate(flags, bitrate); 

            Debug ? printf("bitrate = %zu\n", bitrate) : 0;
        }

        void setBitrateMode(void) {
            ds.Get<bool>() ? setBitrateModeVBR() : setBitrateModeCBR();
        }

        void setChannelMode(void) {
            const uint8_t whichChannelMode = ds.Get<uint8_t>() % 3;
            if ( whichChannelMode == 0 ) {
                lame_set_mode(flags, STEREO);
                Debug ? printf("mode = STEREO\n") : 0;
            } else if ( whichChannelMode == 1 ) {
                lame_set_mode(flags, JOINT_STEREO);
                Debug ? printf("mode = JOINT_STEREO\n") : 0;
            } else if ( whichChannelMode == 2 ) {
                lame_set_mode(flags, MONO);
                Debug ? printf("mode = MONO\n") : 0;
            }
        }

        void setQuality(void) {
            const size_t quality = limits::Quality.Generate(ds);
            lame_set_quality(flags, quality);
            Debug ? printf("quality = %zu\n", quality) : 0;
        }

        void setOutSamplerate(void) {
            const size_t outSamplerate = limits::OutSamplerate.Generate(ds);
            lame_set_out_samplerate(flags, outSamplerate);
            Debug ? printf("out samplerate = %zu\n", outSamplerate) : 0;
        }

        void encodeLoop(void) {
            while ( ds.Get<bool>() ) { 
                /* Get some data to encode */
                const auto inData = ds.GetData(0);

                if ( lame_encode_buffer_interleaved(flags, (short int*)inData.data(), inData.size()/sizeof(int)/2, outBuffer, outBufferSize) < 0 ) {
                    break;
                }

                if ( lame_encode_flush(flags, outBuffer, outBufferSize) < 0 ) {
                    break;
                }
            }
        }
    public:
        EncoderFuzzer(Datasource& ds) :
            ds(ds), outBufferSize(limits::OutBufferSize.Generate(ds))
        {
            flags = lame_init();
            outBuffer = (uint8_t*)malloc(outBufferSize + 1024);
            Debug ? printf("Out buffer size: %zu\n", outBufferSize) : 0;
        }

        void Run(void) {
            setBitrateMode();
            setChannelMode();
            setQuality();
            setOutSamplerate();

            if ( lame_init_params(flags) == -1 ) {
                abort();
            }

            encodeLoop();
        }

        ~EncoderFuzzer() {
            lame_close(flags);
            free(outBuffer);
            outBuffer = nullptr;
        }
};

static bool debug = false;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    char** _argv = *argv;
    for (int i = 0; i < *argc; i++) {
        if ( std::string(_argv[i]) == "--debug") {
            debug = true;
        }
    }

    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    Datasource ds(data, size);

    try {
        if ( debug == false ) {
            EncoderFuzzer<false> encoder(ds);
            encoder.Run();
        } else {
            EncoderFuzzer<true> encoder(ds);
            encoder.Run();
        }
    } catch ( ... ) { }

    return 0;
}
