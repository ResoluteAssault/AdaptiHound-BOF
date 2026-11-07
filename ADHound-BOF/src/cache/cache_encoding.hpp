#pragma once

struct ah_cache_utf8_unit { uint32_t value; size_t consumed; bool valid; };
static ah_cache_utf8_unit ah_cache_read_utf8(const unsigned char *data,size_t size){
    const uint32_t first=data[0];
    if(first<0x80)return {first,1,true};
    unsigned int width=first>=0xc2&&first<=0xdf?2:first>=0xe0&&first<=0xef?3:first>=0xf0&&first<=0xf4?4:0;
    if(!width)return {0xfffd,1,false};
    uint32_t value=first&((1U<<(7-width))-1);size_t read=1;
    for(unsigned int i=1;i<width;++i){
        if(read==size)return {0xfffd,read,false};
        const unsigned char next=data[read];
        if((next&0xc0)!=0x80||(i==1&&((first==0xe0&&next<0xa0)||(first==0xed&&next>=0xa0)||(first==0xf0&&next<0x90)||(first==0xf4&&next>=0x90))))return {0xfffd,read,false};
        value=value<<6|(next&63);++read;
    }
    return {value,read,true};
}
static void ah_cache_encode_utf8(ah_buffer &output,uint32_t value){
    char bytes[4];size_t count=0;
    if(value<0x80){bytes[0]=static_cast<char>(value);count=1;}
    else if(value<0x800){bytes[0]=static_cast<char>(0xc0|(value>>6));bytes[1]=static_cast<char>(0x80|(value&63));count=2;}
    else if(value<0x10000){bytes[0]=static_cast<char>(0xe0|(value>>12));bytes[1]=static_cast<char>(0x80|((value>>6)&63));bytes[2]=static_cast<char>(0x80|(value&63));count=3;}
    else{bytes[0]=static_cast<char>(0xf0|(value>>18));bytes[1]=static_cast<char>(0x80|((value>>12)&63));bytes[2]=static_cast<char>(0x80|((value>>6)&63));bytes[3]=static_cast<char>(0x80|(value&63));count=4;}
    ah_append(&output,bytes,count);
}
static bool ah_cache_decode_file(char *&bytes,size_t &length,size_t limit){
    const auto *input=reinterpret_cast<const unsigned char *>(bytes);
    enum class encoding { utf8,utf16le,utf16be,utf32le,utf32be };
    encoding kind=encoding::utf8;size_t offset=0;
    if(length>=4&&input[0]==0xff&&input[1]==0xfe&&input[2]==0&&input[3]==0){kind=encoding::utf32le;offset=4;}
    else if(length>=4&&input[0]==0&&input[1]==0&&input[2]==0xfe&&input[3]==0xff){kind=encoding::utf32be;offset=4;}
    else if(length>=3&&input[0]==0xef&&input[1]==0xbb&&input[2]==0xbf)offset=3;
    else if(length>=2&&input[0]==0xff&&input[1]==0xfe){kind=encoding::utf16le;offset=2;}
    else if(length>=2&&input[0]==0xfe&&input[1]==0xff){kind=encoding::utf16be;offset=2;}
    if(kind==encoding::utf8){

        bool valid=true;
        for(size_t at=offset;at<length;){const auto unit=ah_cache_read_utf8(input+at,length-at);if(!unit.valid){valid=false;break;}at+=unit.consumed;}
        if(valid){if(offset){for(size_t i=offset;i<length;++i)bytes[i-offset]=bytes[i];length-=offset;bytes[length]=0;}return true;}
    }
    if(offset==length){bytes[0]=0;length=0;return true;}
    ah_buffer output(limit,4096);
    auto word=[&](size_t at,bool little){return little?static_cast<uint32_t>(input[at])|(static_cast<uint32_t>(input[at+1])<<8):(static_cast<uint32_t>(input[at])<<8)|input[at+1];};
    while(offset<length&&!output.failed){
        uint32_t value=0xfffd;
        if(kind==encoding::utf8){const auto unit=ah_cache_read_utf8(input+offset,length-offset);value=unit.value;offset+=unit.consumed;}
        else if(kind==encoding::utf16le||kind==encoding::utf16be){
            const bool little=kind==encoding::utf16le;
            if(length-offset<2)offset=length;
            else{
                value=word(offset,little);offset+=2;
                if(value>=0xd800&&value<=0xdbff){
                    const uint32_t low=length-offset>=2?word(offset,little):0;
                    if(low>=0xdc00&&low<=0xdfff){value=0x10000+((value-0xd800)<<10)+low-0xdc00;offset+=2;}
                    else value=0xfffd;
                }else if(value>=0xdc00&&value<=0xdfff)value=0xfffd;
            }
        }else{
            if(length-offset<4)offset=length;
            else{
                value=kind==encoding::utf32le?word(offset,true)|(word(offset+2,true)<<16):(word(offset,false)<<16)|word(offset+2,false);
                offset+=4;if(value>0x10ffff||(value>=0xd800&&value<=0xdfff))value=0xfffd;
            }
        }
        ah_cache_encode_utf8(output,value);
    }
    const size_t decoded=output.length;AH_TEXT(&output,"\0");
    if(output.failed)return false;
    ah_free(bytes);bytes=output.data;length=decoded;output.data=nullptr;
    return true;
}
