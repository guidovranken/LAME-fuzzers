/* LAME encoder fuzzer by Guido Vranken <guidovranken@gmail.com> */

#include <fuzzing/datasource/datasource.hpp>
#include <stdexcept>
#include <memory>
#include <string>
#include <stdint.h>
#include <stdlib.h>
#include <cmath>
#include <lame.h>
#include <sstream>

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
                /* If not within bounds, default to the minimum allowed value */
                return min;
            }

            return val;
        }

        template <typename T = uint32_t>
        size_t Generate(fuzzing::datasource::Datasource& ds) {
            const size_t ret = ds.Get<T>();
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
    static Limit Quality(0, 9);
    static Limit LowpassFrequency(0, 1000000);
    static Limit HighpassFrequency(1000, 1000000);
    static Limit HighpassWidth(1000, 1000000);
    static Limit CompressionRatio(1, 100);
}

#define _(expr) Debug ? printf("%s\n", #expr) : 0; expr;

class EncoderCoreBase {
    public:
        EncoderCoreBase(void) { }
        virtual ~EncoderCoreBase() { }
        virtual bool Run(uint8_t* outBuffer, const size_t outBufferSize, const bool mono) = 0;
};


template <typename T> bool isNAN(const T& val) {
    (void)val;

    return false;
}

template <> bool isNAN<float>(const float& val) {
    return std::isnan(val);
}

template <> bool isNAN<double>(const double& val) {
    return std::isnan(val);
}

std::string debug_define_size_t(const std::string name, const size_t val) {
    return "const size_t " + name + " = " + std::to_string(val) + ";";
}

template <typename T>
struct DebugDefineArray {
    static std::string Str(const std::string name, const std::string typeName, const T* inData, const size_t inDataSize, const bool indent) {
        std::stringstream ret;

        if ( indent ) {
            ret << "\t";
        }

        ret << "const " << typeName << "  " + name + "[] = {\n";

        if ( indent ) {
            ret << "\t";
        }

        for (size_t i = 0; i < inDataSize; i++) {
            if ( i && !(i % 16) ) {
                ret << "\n";
                if ( indent ) {
                    ret << "\t";
                }
            }

            ret << "\t" << std::to_string(inData[i]) << ", ";
        }
        ret << "\n";

        if ( indent ) {
            ret << "\t";
        }

        ret << "};\n";

        return ret.str();
    }
};

template <typename T, bool Debug>
class EncoderCore : public EncoderCoreBase {
    private:
        Datasource& ds;
        lame_global_flags* flags;

        std::vector< std::vector<T> > inDataV;
        typename std::vector< std::vector<T> >::iterator it;
        const bool useInterleavingFunction;
        const bool useIEEEFunction;

        void getInputData(void) {
            while ( ds.Get<bool>() ) {
                const auto data = ds.GetData(0);

                /* Round to a multiple of sizeof(T) */
                const size_t copySize = data.size() - (data.size() % sizeof(T));

                std::vector<T> toInsert;
                toInsert.resize( data.size() / sizeof(T) );

                memcpy(toInsert.data(), data.data(), copySize);

                /* Correct NAN values */
                for (size_t i = 0; i < toInsert.size(); i++) {
                    if ( isNAN(toInsert[i]) ) {
                        toInsert[i] = {};
                    }
                }

                inDataV.push_back(toInsert);
            }
            it = inDataV.begin();
        }

        template <typename _T, long Min, long Max>
        struct InputCorrect {
            static void Correct(_T* inData, const size_t inDataSize) {
                if ( inData == nullptr ) {
                    return;
                }

                for (size_t i = 0; i < inDataSize; i++) {
                    if ( inData[i] > Max ) {
                        inData[i] = Max;
                    } else if ( inData[i] < Min ) {
                        inData[i] = Min;
                    }
                }
            }
        };

        template <typename T_, bool Debug_>
        struct EncodeSingle {
            static int encode(
                    lame_global_flags* flags,
                    T* inData,
                    const size_t inDataSize,
                    uint8_t* outBuffer,
                    const size_t outBufferSize,
                    bool useInterleavedFunction,
                    bool useIEEEFunction);
        };

        template<bool Debug_> struct EncodeSingle<short int, Debug_> {
            static int encode(
                    lame_global_flags* flags,
                    short int* inDataL,
                    short int* inDataR,
                    const size_t inDataSize,
                    uint8_t* outBuffer,
                    const size_t outBufferSize,
                    bool useInterleavingFunction,
                    bool useIEEEFunction) {
                /* Not applicable for short int */
                (void)useIEEEFunction;

                if ( useInterleavingFunction == false ) {
                    Debug ? printf("{\n") : 0;

                    Debug ? printf("\t%s\n", debug_define_size_t("inDataSize", inDataSize).c_str()) : 0;

                    Debug ? printf("%s\n", DebugDefineArray<short int>::Str("inDataL", "short int", inDataL, inDataSize, true).c_str()) : 0;
                    Debug ? printf("%s\n", DebugDefineArray<short int>::Str("inDataR", "short int", inDataR, inDataSize, true).c_str()) : 0;

                    const int ret = lame_encode_buffer(flags, inDataL, inDataR, inDataSize, outBuffer, outBufferSize);

                    Debug ? printf("\t// (returns %d)\n", ret) : 0;

                    Debug ? printf("}\n") : 0;

                    return ret;
                } else {
                    Debug ? printf("{\n") : 0;

                    Debug ? printf("\t%s\n", debug_define_size_t("inDataSize", inDataSize).c_str()) : 0;

                    Debug ? printf("%s\n", DebugDefineArray<short int>::Str("inDataL", "short int", inDataL, inDataSize * 2, true).c_str()) : 0;

                    const int ret = lame_encode_buffer_interleaved(flags, inDataL, inDataSize, outBuffer, outBufferSize);

                    Debug ? printf("\t// (returns %d)\n", ret) : 0;

                    Debug ? printf("}\n") : 0;

                    return ret;
                }
            }
        };

        template<bool Debug_> struct EncodeSingle<int, Debug_> {
            static int encode(
                    lame_global_flags* flags,
                    int* inDataL,
                    int* inDataR,
                    const size_t inDataSize,
                    uint8_t* outBuffer,
                    const size_t outBufferSize,
                    bool useInterleavingFunction,
                    bool useIEEEFunction ) {
                /* Not applicable for int */
                (void)useIEEEFunction;

                if ( useInterleavingFunction == false ) {
                    Debug ? printf("{\n") : 0;

                    Debug ? printf("\t%s\n", debug_define_size_t("inDataSize", inDataSize).c_str()) : 0;

                    Debug ? printf("%s\n", DebugDefineArray<int>::Str("inDataL", "int", inDataL, inDataSize, true).c_str()) : 0;
                    Debug ? printf("%s\n", DebugDefineArray<int>::Str("inDataR", "int", inDataR, inDataSize, true).c_str()) : 0;

                    Debug ?
                        printf("\tlame_encode_buffer_int(flags, inDataL, inDataR, inDataSize, outBuffer, outBufferSize);\n")
                        : 0;

                    const int ret = lame_encode_buffer_int(flags, inDataL, inDataR, inDataSize, outBuffer, outBufferSize);

                    Debug ? printf("\t// (returns %d)\n", ret) : 0;

                    Debug ? printf("}\n") : 0;

                    return ret;
                } else {
                    Debug ? printf("{\n") : 0;

                    Debug ? printf("\t%s\n", debug_define_size_t("inDataSize", inDataSize).c_str()) : 0;

                    Debug ? printf("%s\n", DebugDefineArray<int>::Str("inDataL", "int", inDataL, inDataSize * 2, true).c_str()) : 0;

                    Debug ?
                        printf("\tlame_encode_buffer_interleaved_int(flags, inDataL, inDataSize, outBuffer, outBufferSize);\n")
                        : 0;

                    const int ret = lame_encode_buffer_interleaved_int(flags, inDataL, inDataSize, outBuffer, outBufferSize);

                    Debug ? printf("\t// (returns %d)\n", ret) : 0;

                    Debug ? printf("}\n") : 0;

                    return ret;
                }
            }
        };

        template<bool Debug_> struct EncodeSingle<long, Debug_> {
            static int encode(
                    lame_global_flags* flags,
                    long* inDataL,
                    long* inDataR,
                    const size_t inDataSize,
                    uint8_t* outBuffer,
                    const size_t outBufferSize,
                    bool useInterleavingFunction,
                    bool useIEEEFunction) {
                /* Not applicable for long */
                (void)useIEEEFunction;

                if ( useInterleavingFunction == false ) {
                    InputCorrect<long, -32768, 32768>::Correct(inDataL, inDataSize);
                    InputCorrect<long, -32768, 32768>::Correct(inDataR, inDataSize);

                    Debug ? printf("{\n") : 0;

                    Debug ? printf("\t%s\n", debug_define_size_t("inDataSize", inDataSize).c_str()) : 0;

                    Debug ? printf("%s\n", DebugDefineArray<long>::Str("inDataL", "long", inDataL, inDataSize, true).c_str()) : 0;
                    Debug ? printf("%s\n", DebugDefineArray<long>::Str("inDataR", "long", inDataR, inDataSize, true).c_str()) : 0;

                    Debug ?
                        printf("\tlame_encode_buffer_long(flags, inDataL, inDataR, inDataSize, outBuffer, outBufferSize);\n")
                        : 0;

                    const int ret = lame_encode_buffer_long(flags, inDataL, inDataR, inDataSize, outBuffer, outBufferSize);

                    Debug ? printf("\t// (returns %d)\n", ret) : 0;

                    Debug ? printf("}\n") : 0;

                    return ret;
                } else {
                    Debug ? printf("{\n") : 0;

                    Debug ? printf("\t%s\n", debug_define_size_t("inDataSize", inDataSize).c_str()) : 0;

                    Debug ? printf("%s\n", DebugDefineArray<long>::Str("inDataL", "long", inDataL, inDataSize * 2, true).c_str()) : 0;

                    Debug ?
                        printf("\tlame_encode_buffer_long2(flags, inDataL, inDataR, inDataSize, outBuffer, outBufferSize);\n")
                        : 0;

                    /* Not actually interleaved */
                    const int ret = lame_encode_buffer_long2(flags, inDataL, inDataR, inDataSize, outBuffer, outBufferSize);

                    Debug ? printf("\t// (returns %d)\n", ret) : 0;

                    Debug ? printf("}\n") : 0;

                    return ret;
                }
            }
        };

        template<bool Debug_> struct EncodeSingle<float, Debug_> {
            static int encode(
                    lame_global_flags* flags,
                    float* inDataL,
                    float* inDataR,
                    const size_t inDataSize,
                    uint8_t* outBuffer,
                    const size_t outBufferSize,
                    bool useInterleavingFunction,
                    bool useIEEEFunction) {

                if ( useInterleavingFunction == false ) {
                    if ( useIEEEFunction == false ) {
                        InputCorrect<float, -32768, 32768>::Correct(inDataL, inDataSize);
                        InputCorrect<float, -32768, 32768>::Correct(inDataR, inDataSize);

                        Debug ? printf("{\n") : 0;

                        Debug ? printf("\t%s\n", debug_define_size_t("inDataSize", inDataSize).c_str()) : 0;

                        Debug ? printf("%s\n", DebugDefineArray<float>::Str("inDataL", "float", inDataL, inDataSize, true).c_str()) : 0;
                        Debug ? printf("%s\n", DebugDefineArray<float>::Str("inDataR", "float", inDataR, inDataSize, true).c_str()) : 0;

                        Debug ?
                            printf("\tlame_encode_buffer_float(flags, inDataL, inDataR, inDataSize, outBuffer, outBufferSize);\n")
                            : 0;

                        const int ret = lame_encode_buffer_float(flags, inDataL, inDataR, inDataSize, outBuffer, outBufferSize);

                        Debug ? printf("\t// (returns %d)\n", ret) : 0;

                        Debug ? printf("}\n") : 0;

                        return ret;
                    } else {
                        InputCorrect<float, -1, 1>::Correct(inDataL, inDataSize);
                        InputCorrect<float, -1, 1>::Correct(inDataR, inDataSize);

                        Debug ? printf("{\n") : 0;

                        Debug ? printf("\t%s\n", debug_define_size_t("inDataSize", inDataSize).c_str()) : 0;

                        Debug ? printf("%s\n", DebugDefineArray<float>::Str("inDataL", "float", inDataL, inDataSize, true).c_str()) : 0;
                        Debug ? printf("%s\n", DebugDefineArray<float>::Str("inDataR", "float", inDataR, inDataSize, true).c_str()) : 0;

                        Debug ?
                            printf("\tlame_encode_buffer_ieee_float(flags, inDataL, inDataR, inDataSize, outBuffer, outBufferSize);\n")
                            : 0;

                        const int ret = lame_encode_buffer_ieee_float(flags, inDataL, inDataR, inDataSize, outBuffer, outBufferSize);

                        Debug ? printf("\t// (returns %d)\n", ret) : 0;

                        Debug ? printf("}\n") : 0;

                        return ret;
                    }
                } else {
                    if ( useIEEEFunction == true ) {
                        InputCorrect<float, -1, 1>::Correct(inDataL, inDataSize * 2);

                        Debug ? printf("{\n") : 0;

                        Debug ? printf("\t%s\n", debug_define_size_t("inDataSize", inDataSize * 2).c_str()) : 0;

                        Debug ? printf("%s\n", DebugDefineArray<float>::Str("inDataL", "float", inDataL, inDataSize * 2, true).c_str()) : 0;

                        Debug ?
                            printf("\tlame_encode_buffer_interleaved_ieee_float(flags, inDataL, inDataSize, outBuffer, outBufferSize);\n")
                            : 0;

                        const int ret = lame_encode_buffer_interleaved_ieee_float(flags, inDataL, inDataSize, outBuffer, outBufferSize);

                        Debug ? printf("\t// (returns %d)\n", ret) : 0;

                        Debug ? printf("}\n") : 0;

                        return ret;
                    } else {
                        /* No function for interleaved float */
                        return -1;
                    }
                }
            }
        };

        template<bool Debug_> struct EncodeSingle<double, Debug_> {
            int static encode(
                    lame_global_flags* flags,
                    double* inDataL,
                    double* inDataR,
                    const size_t inDataSize,
                    uint8_t* outBuffer,
                    const size_t outBufferSize,
                    bool useInterleavingFunction,
                    bool useIEEEFunction) {

                if ( useInterleavingFunction == true ) {
                    if ( useIEEEFunction == false ) {
                        /* No non-IEEE function for interleaved double */
                        return -1;
                    } else {
                        InputCorrect<double, -1, 1>::Correct(inDataL, inDataSize);

                        Debug ? printf("{\n") : 0;

                        Debug ? printf("\t%s\n", debug_define_size_t("inDataSize", inDataSize).c_str()) : 0;

                        Debug ? printf("%s\n", DebugDefineArray<double>::Str("inDataL", "double", inDataL, inDataSize, true).c_str()) : 0;

                        Debug ?
                            printf("\tlame_encode_buffer_ieee_double(flags, inDataL, inDataR, inDataSize, outBuffer, outBufferSize);\n")
                            : 0;

                        const int ret = lame_encode_buffer_ieee_double(flags, inDataL, inDataR, inDataSize, outBuffer, outBufferSize);

                        Debug ? printf("\t// (returns %d)\n", ret) : 0;

                        Debug ? printf("}\n") : 0;

                        return ret;
                    }
                } else {
                    if ( useIEEEFunction == false ) {
                        InputCorrect<double, -1, 1>::Correct(inDataL, inDataSize * 2);
                        InputCorrect<double, -1, 1>::Correct(inDataR, inDataSize * 2);

                        Debug ? printf("{\n") : 0;

                        Debug ? printf("\t%s\n", debug_define_size_t("inDataSize", inDataSize).c_str()) : 0;

                        Debug ? printf("%s\n", DebugDefineArray<double>::Str("inDataL", "double", inDataL, inDataSize * 2, true).c_str()) : 0;

                        Debug ?
                            printf("lame_encode_buffer_interleaved_ieee_double(flags, inDataL, inDataSize, outBuffer, outBufferSize);\n")
                            : 0;

                        const int ret = lame_encode_buffer_interleaved_ieee_double(flags, inDataL, inDataSize, outBuffer, outBufferSize);


                        Debug ? printf("\t// (returns %d)\n", ret) : 0;

                        Debug ? printf("}\n") : 0;

                        return ret;
                    } else {
                        /* No non-IEEE function for double */
                        return -1;
                    }
                }
            }
        };

        int encode(std::vector<T>& inData, uint8_t* outBuffer, const size_t outBufferSize, const bool mono) {
            if ( useInterleavingFunction && mono ) {
                return -1;
            }

            if ( mono == true ) {
                return EncodeSingle<T, Debug>::encode(flags, inData.data(), nullptr, inData.size() / 2, outBuffer, outBufferSize, useInterleavingFunction, useIEEEFunction);
            } else if ( useInterleavingFunction ) {
                const size_t numSamples = inData.size() / 2;

                std::vector<T> inDataCopy;
                inDataCopy.resize(numSamples);

                memcpy(inDataCopy.data(), inData.data(), numSamples * 2);

                return EncodeSingle<T, Debug>::encode(flags, inData.data(), nullptr, numSamples, outBuffer, outBufferSize, useInterleavingFunction, useIEEEFunction);
            } else {
                std::vector<T> inDataL, inDataR;

                inDataL.resize(inData.size() / 2);
                inDataR.resize(inData.size() / 2);

                const size_t numSamples = inData.size() / 2;
                memcpy(inDataL.data(), inData.data(), numSamples);
                memcpy(inDataR.data(), inData.data() + numSamples, numSamples);

                return EncodeSingle<T, Debug>::encode(flags, inDataR.data(), inDataL.data(), numSamples, outBuffer, outBufferSize, useInterleavingFunction, useIEEEFunction);
            }
        }

        int flush(uint8_t* outBuffer, const size_t outBufferSize) {
            if ( ds.Get<bool>() ) {
                /* No flush */
                return 0;
            }

            if ( ds.Get<bool>() ) {
                Debug ?
                    printf("lame_encode_flush(flags, outBuffer, outBufferSize);\n")
                    : 0;

                const int ret = lame_encode_flush(flags, outBuffer, outBufferSize);

                if ( ret > static_cast<int>(outBufferSize) ) {
                    printf("lame_encode_flush reported more output bytes than the buffer can hold\n");

                    abort();
                }

                Debug ? printf("// (returns %d)\n", ret) : 0;

                return ret;
            } else {
#if 0
                /* XXX disabled because it prints:
                 * "strange error flushing buffer ..."
                 */
                Debug ?
                    printf("lame_encode_flush_nogap(flags, outBuffer, outBufferSize);\n")
                    : 0;

                const int ret = lame_encode_flush_nogap(flags, outBuffer, outBufferSize);

                Debug ? printf("// (returns %d)\n", ret) : 0;

                return ret;
#else
                return 0;
#endif
            }
        }
    public:
        EncoderCore(Datasource& ds, lame_global_flags* flags) :
            EncoderCoreBase(),
            ds(ds),
            flags(flags),
            it(inDataV.end()),
            useInterleavingFunction( ds.Get<bool>() ),
            useIEEEFunction( ds.Get<bool>() )
        {
            getInputData();
        }

        bool Run(uint8_t* outBuffer, const size_t outBufferSize, const bool mono) override {
            if ( it == inDataV.end() ) {
                return false;
            }

            auto& inData = *it;
            it++;

            const int encodeRet = encode(inData, outBuffer, outBufferSize, mono);

            if ( encodeRet < 0 ) {
                return false;
            }

            if ( encodeRet > static_cast<int>(outBufferSize) ) {
                printf("encode reported more output bytes than the buffer can hold\n");

                abort();
            }

            if ( flush(outBuffer, outBufferSize) < 0 ) {
                return false;
            }

            if ( encodeRet == 0 ) {
                return false;
            }

            return true;
        }
};

/* In the interest of speed, let Debug be a template parameter,
 * so that in non-debug mode, all debug checks will be optimized away.
 */
template <bool Debug>
class EncoderFuzzer {
    private:
        Datasource& ds;
        lame_global_flags* flags = nullptr;
        uint8_t* outBuffer = nullptr;
        const size_t outBufferSize;
        std::vector< std::vector<int> > inDataV;
        bool mono = false;

        void setBitrateModeVBR_RH(void) {
            _(lame_set_VBR(flags, vbr_rh););
        }

        void setBitrateModeVBR_MTRH(void) {
            _(lame_set_VBR(flags, vbr_mtrh););
        }

        void setBitrateModeVBR_ABR(void) {
            _(lame_set_VBR(flags, vbr_abr););

            const size_t ABRBitrate = limits::ABRBitrate.Generate(ds);

            Debug ? printf("lame_set_VBR_mean_bitrate_kbps(flags, %zu);\n", ABRBitrate) : 0;

            lame_set_VBR_mean_bitrate_kbps(flags, ABRBitrate);
        }

        size_t setMinBitrate(void) {
            if ( ds.Get<bool>() ) return 0;

            const size_t minBitrate = limits::MinBitrate.Generate(ds);

            Debug ? printf("lame_set_VBR_min_bitrate_kbps(flags, %zu);\n", minBitrate) : 0;

            lame_set_VBR_min_bitrate_kbps(flags, minBitrate);

            return minBitrate;
        }

        void setMaxBitrate(const size_t minBitrate) {
            if ( ds.Get<bool>() ) return;

            const size_t maxBitrate = limits::MaxBitrate.Generate(ds);
            if ( minBitrate > maxBitrate ) {
                throw std::runtime_error("minBitrate > maxBitrate");
            }

            Debug ? printf("lame_set_VBR_max_bitrate_kbps(flags, %zu);\n", maxBitrate) : 0;

            lame_set_VBR_max_bitrate_kbps(flags, maxBitrate);
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
            _(lame_set_VBR(flags, vbr_off););

            const size_t bitrate = limits::CBRBitrate.Generate(ds);

            Debug ? printf("lame_set_brate(flags, %zu);\n", bitrate) : 0;

            _(lame_set_brate(flags, bitrate););
        }

        void setBitrateMode(void) {
            ds.Get<bool>() ? setBitrateModeVBR() : setBitrateModeCBR();
        }

        void setInputChannels(void) {
            const int numChannels = ds.Get<bool>() ? 1 : 2;

            Debug ? printf("lame_set_num_channels(flags, %d);\n", numChannels) : 0;

            lame_set_num_channels(flags, numChannels);

            if ( numChannels == 1 ) {
                mono = true;
            }
        }

        void setChannelMode(void) {
            const uint8_t whichChannelMode = ds.Get<uint8_t>() % 3;
            if ( whichChannelMode == 0 ) {
                _(lame_set_mode(flags, STEREO););
            } else if ( whichChannelMode == 1 ) {
                _(lame_set_mode(flags, JOINT_STEREO););
            } else if ( whichChannelMode == 2 ) {
                _(lame_set_mode(flags, MONO););
            }
        }

        void setQuality(void) {
            const size_t quality = limits::Quality.Generate<uint8_t>(ds);

            Debug ? printf("lame_set_quality(flags, %zu);\n", quality) : 0;

            lame_set_quality(flags, quality);
        }

        void setOutSamplerate(void) {
            const size_t outSamplerate = limits::OutSamplerate.Generate(ds);

            Debug ? printf("lame_set_out_samplerate(flags, %zu);\n", outSamplerate) : 0;

            lame_set_out_samplerate(flags, outSamplerate);
        }

        void setID3(void) {
            /* Optionally set various ID3 fields */

            if ( ds.Get<bool>() ) {
                id3tag_init(flags);

                if ( ds.Get<bool>() ) {
                    const std::string title = ds.Get<std::string>();

                    Debug ? printf("id3tag_set_title(flags, %s);\n", title.c_str()) : 0;

                    id3tag_set_title(flags, title.c_str());
                }

                if ( ds.Get<bool>() ) {
                    const std::string artist = ds.Get<std::string>();

                    Debug ? printf("id3tag_set_artist(flags, %s);\n", artist.c_str()) : 0;

                    id3tag_set_artist(flags, artist.c_str());
                }

                if ( ds.Get<bool>() ) {
                    const std::string album = ds.Get<std::string>();

                    Debug ? printf("id3tag_set_album(flags, %s);\n", album.c_str()) : 0;

                    id3tag_set_album(flags, album.c_str());
                }

                if ( ds.Get<bool>() ) {
                    const std::string year = ds.Get<std::string>();

                    Debug ? printf("id3tag_set_year(flags, %s);\n", year.c_str()) : 0;

                    id3tag_set_year(flags, year.c_str());
                }

                if ( ds.Get<bool>() ) {
                    const std::string comment = ds.Get<std::string>();

                    Debug ? printf("id3tag_set_comment(flags, %s);\n", comment.c_str()) : 0;

                    id3tag_set_comment(flags, comment.c_str());
                }

                if ( ds.Get<bool>() ) {
                    const std::string track = ds.Get<std::string>();

                    Debug ? printf("id3tag_set_track(flags, %s);\n", track.c_str()) : 0;

                    id3tag_set_track(flags, track.c_str());
                }

                if ( ds.Get<bool>() ) {
                    const std::string genre = ds.Get<std::string>();

                    Debug ? printf("id3tag_set_genre(flags, %s);\n", genre.c_str()) : 0;

                    id3tag_set_genre(flags, genre.c_str());
                }

                if ( ds.Get<bool>() ) {
                    const std::string fieldvalue = ds.Get<std::string>();

                    Debug ? printf("id3tag_set_fieldvalue(flags, %s);\n", fieldvalue.c_str()) : 0;

                    id3tag_set_fieldvalue(flags, fieldvalue.c_str());
                }

                if ( ds.Get<bool>() ) {
                    const auto albumArt = ds.GetData(0);

                    /* TODO dump albumArt in debug mode */
                    id3tag_set_albumart(flags, (const char*)albumArt.data(), albumArt.size());
                }
            }
        }

        void setFilters(void) {
            if ( ds.Get<bool>() ) {
                const size_t lowpassFreq = limits::LowpassFrequency.Generate(ds);

                Debug ? printf("lame_set_lowpassfreq(flags, %zu);\n", lowpassFreq) : 0;

                lame_set_lowpassfreq(flags, lowpassFreq);
            }

            if ( ds.Get<bool>() ) {
                const size_t highpassFreq = limits::HighpassFrequency.Generate(ds);

                Debug ? printf("lame_set_highpassfreq(flags, %zu);\n", highpassFreq) : 0;

                lame_set_highpassfreq(flags, highpassFreq);
            }

            if ( ds.Get<bool>() ) {

                const size_t highpassWidth = limits::HighpassWidth.Generate(ds);

                Debug ? printf("lame_set_highpasswidth(flags, %zu);\n", highpassWidth) : 0;

                lame_set_highpasswidth(flags, highpassWidth);
            }
        }


        void setMisc(void) {
            if ( ds.Get<bool>() ) {
                _(lame_set_strict_ISO(flags, MDB_STRICT_ISO););
            }

            if ( ds.Get<bool>() ) {
                _(lame_set_bWriteVbrTag(flags, 0););
            }

            if ( ds.Get<bool>() ) {
                _(lame_set_copyright(flags, 1););
            }

            if ( ds.Get<bool>() ) {
                _(lame_set_original(flags, 1););
            }

            if ( ds.Get<bool>() ) {
                _(lame_set_error_protection(flags, 1););
            }

            if ( ds.Get<bool>() ) {
                /* Crashes */
                /* _(lame_set_free_format(flags, 1);); */
            }
        }

    public:
        EncoderFuzzer(Datasource& ds) :
            ds(ds), outBufferSize(limits::OutBufferSize.Generate(ds))
        {
            Debug ?
                printf("lame_global_flags* flags = lame_init();\n")
                : 0;
            flags = lame_init();

            Debug ?
                printf("const size_t outBufferSize = %zu\n", outBufferSize)
                : 0;
            Debug ?
                printf("unsigned char outBuffer[outBufferSize];\n")
                : 0;

            outBuffer = (uint8_t*)malloc(outBufferSize + 1024 /* Add 1024 due to crash */);
        }

        void Run(void) {

            std::unique_ptr<EncoderCoreBase> encoder = nullptr;

            const uint8_t whichSampleSize = ds.Get<uint8_t>() % 5;
            if ( whichSampleSize == 0 ) {
                encoder = std::make_unique<EncoderCore<short int, Debug>>(ds, flags);
            } else if ( whichSampleSize == 1 ) {
                encoder = std::make_unique<EncoderCore<int, Debug>>(ds, flags);
            } else if ( whichSampleSize == 2 ) {
                encoder = std::make_unique<EncoderCore<long, Debug>>(ds, flags);
            } else if ( whichSampleSize == 3 ) {
                /* Disabled due to crash */
                return;
                encoder = std::make_unique<EncoderCore<float, Debug>>(ds, flags);
            } else if ( whichSampleSize == 4 ) {
                /* Disabled due to crash */
                return;
                encoder = std::make_unique<EncoderCore<double, Debug>>(ds, flags);
            }

            setInputChannels();
            setBitrateMode();
            setChannelMode();
            setQuality();
            setOutSamplerate();
            setID3();
            setFilters();
            setMisc();

            Debug ? printf("lame_init_params(flags);\n") : 0;

            if ( lame_init_params(flags) == -1 ) {
                abort();
            }

            while ( encoder->Run(outBuffer, outBufferSize, mono) ) { }
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
