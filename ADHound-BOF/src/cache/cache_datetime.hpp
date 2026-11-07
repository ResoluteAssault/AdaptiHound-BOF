#pragma once
#include "../../../common/core/native_api.hpp"

class ah_cache_datetime final {
    enum : int64_t {day_ticks=864000000000LL,minute_ticks=600000000LL,maximum=3155378975999999999LL};
    struct parts { unsigned int year,month,day,hour,minute,second,fraction; };
    static bool leap(unsigned int y){return y%4==0&&(y%100!=0||y%400==0);}
    static unsigned int month_days(unsigned int y,unsigned int m){const unsigned char days[]={31,28,31,30,31,30,31,31,30,31,30,31};return days[m-1]+(m==2&&leap(y)?1:0);}
    static int64_t year_days(unsigned int y){const int64_t n=y-1;return 365*n+n/4-n/100+n/400;}
    static bool ticks(const parts &p,int64_t &value){
        if(p.year<1||p.year>9999||p.month<1||p.month>12||p.day<1||p.day>month_days(p.year,p.month)||p.hour>24||p.minute>59||p.second>59||(p.hour==24&&(p.minute||p.second||p.fraction)))return false;
        int64_t days=year_days(p.year)+p.day-1;for(unsigned int m=1;m<p.month;++m)days+=month_days(p.year,m);
        value=days*day_ticks+static_cast<int64_t>(p.hour*3600+p.minute*60+p.second)*10000000LL+p.fraction;
        return value<=maximum;
    }
    static parts split(int64_t value){
        const int64_t days=value/day_ticks;unsigned int low=1,high=10000;
        while(low+1<high){unsigned int middle=(low+high)/2;if(year_days(middle)<=days)low=middle;else high=middle;}
        unsigned int left=static_cast<unsigned int>(days-year_days(low)),month=1;while(left>=month_days(low,month)){left-=month_days(low,month);++month;}
        int64_t time=value%day_ticks;parts p={low,month,left+1,static_cast<unsigned int>(time/36000000000LL),static_cast<unsigned int>(time/600000000LL%60),static_cast<unsigned int>(time/10000000LL%60),static_cast<unsigned int>(time%10000000LL)};return p;
    }
    static bool local(int64_t utc,int64_t &value,int &offset){
        const int64_t bounded=utc<0?0:utc>maximum?maximum:utc;const parts p=split(bounded);
        SYSTEMTIME input={},output={};input.wYear=static_cast<WORD>(p.year);input.wMonth=static_cast<WORD>(p.month);input.wDay=static_cast<WORD>(p.day);input.wHour=static_cast<WORD>(p.hour);input.wMinute=static_cast<WORD>(p.minute);input.wSecond=static_cast<WORD>(p.second);input.wMilliseconds=static_cast<WORD>(p.fraction/10000);
        ah_native_library kernel(L"kernel32.dll");
        using convert_ex_fn=BOOL (WINAPI *)(const void *,const SYSTEMTIME *,SYSTEMTIME *);
        auto convert_ex=kernel.find<convert_ex_fn>("SystemTimeToTzSpecificLocalTimeEx");
        auto convert=kernel.find<decltype(&SystemTimeToTzSpecificLocalTime)>("SystemTimeToTzSpecificLocalTime");
        const bool converted=convert_ex?convert_ex(nullptr,&input,&output)!=0:convert&&convert(nullptr,&input,&output)!=0;
        int64_t local_ticks=0;
        if(converted&&ticks({output.wYear,output.wMonth,output.wDay,output.wHour,output.wMinute,output.wSecond,static_cast<unsigned int>(output.wMilliseconds)*10000+p.fraction%10000},local_ticks))offset=static_cast<int>((local_ticks-bounded)/minute_ticks);
        else{

            auto query=kernel.find<decltype(&GetTimeZoneInformation)>("GetTimeZoneInformation");TIME_ZONE_INFORMATION zone={};
            if(!query||query(&zone)==TIME_ZONE_ID_INVALID||(zone.DaylightDate.wMonth&&zone.DaylightBias!=zone.StandardBias))return false;
            offset=-(zone.Bias+zone.StandardBias);
        }
        value=utc+static_cast<int64_t>(offset)*minute_ticks;if(value<0)value=0;if(value>maximum)value=maximum;return true;
    }
    static void number(char *&out,unsigned int value,unsigned int width){for(unsigned int divisor=width==4?1000:10;divisor;divisor/=10)*out++=static_cast<char>('0'+value/divisor%10);}
    static void format(int64_t value,bool utc,bool localized,int offset,char (&output)[64]){
        const parts p=split(value);char *out=output;
        number(out,p.year,4);*out++='-';number(out,p.month,2);*out++='-';number(out,p.day,2);*out++='T';number(out,p.hour,2);*out++=':';number(out,p.minute,2);*out++=':';number(out,p.second,2);
        if(p.fraction){*out++='.';unsigned int fraction=p.fraction;for(unsigned int divisor=1000000;divisor;divisor/=10)*out++=static_cast<char>('0'+fraction/divisor%10);while(out[-1]=='0')--out;}
        if(utc)*out++='Z';else if(localized){*out++=offset<0?'-':'+';const unsigned int magnitude=static_cast<unsigned int>(offset<0?-offset:offset);number(out,magnitude/60,2);*out++=':';number(out,magnitude%60,2);}
        *out=0;
    }
    static bool digits(const char *text,size_t end,size_t &at,unsigned int minimum,unsigned int maximum_digits,unsigned int &value){
        const size_t begin=at;value=0;while(at<end&&at-begin<maximum_digits&&text[at]>='0'&&text[at]<='9')value=value*10+static_cast<unsigned int>(text[at++]-'0');return at-begin>=minimum;
    }
    static bool microsoft(const char *text,size_t size,char (&output)[64]){
        if(size<9||text[0]!='/'||text[1]!='D'||text[2]!='a'||text[3]!='t'||text[4]!='e'||text[5]!='('||text[size-2]!=')'||text[size-1]!='/')return false;
        size_t at=6;const bool negative=text[at]=='-';if(negative)++at;const size_t begin=at;uint64_t milliseconds=0;
        while(at<size-2&&text[at]>='0'&&text[at]<='9'){const unsigned int digit=static_cast<unsigned int>(text[at++]-'0');if(milliseconds>(static_cast<uint64_t>(INT64_MAX)-digit)/10)return false;milliseconds=milliseconds*10+digit;}
        if(at==begin)return false;
        bool localized=false;
        if(at<size-2){
            if(text[at]!='+'&&text[at]!='-')return false;
            ++at;unsigned int hour=0,minute=0;if(!digits(text,size-2,at,2,2,hour))return false;
            if(at<size-2&&!digits(text,size-2,at,2,2,minute))return false;
            if(at!=size-2)return false;
            localized=true;
        }
        const int64_t epoch=621355968000000000LL;
        if(milliseconds>static_cast<uint64_t>(negative?epoch/10000:(maximum-epoch)/10000))return false;
        int64_t value=epoch+(negative?-static_cast<int64_t>(milliseconds):static_cast<int64_t>(milliseconds))*10000;int offset=0;
        if(localized&&!local(value,value,offset))return false;
        format(value,!localized,localized,offset,output);return true;
    }
public:
    static bool parse(const char *text,size_t size,char (&output)[64]){
        if(!text||!size)return false;
        if(text[0]=='/')return microsoft(text,size,output);
        size_t begin=0,end=size;
        while(begin<end){const unsigned int width=ah_timespan_space(text+begin);if(!width||width>end-begin)break;begin+=width;}
        while(end>begin&&text[end-1]==0)--end;
        while(end>begin){size_t start=end-1;while(start>begin&&(static_cast<unsigned char>(text[start])&0xc0)==0x80)--start;if(ah_timespan_space(text+start)!=end-start)break;end=start;}
        size_t at=begin;parts p={};
        if(!digits(text,end,at,4,4,p.year)||at==end||text[at++]!='-'||!digits(text,end,at,2,2,p.month)||at==end||text[at++]!='-'||!digits(text,end,at,2,2,p.day))return false;
        bool strict_iso=false,had_time=false;unsigned int fraction_digits=0;
        if(at<end&&(text[at]=='T'||text[at]=='t'||text[at]==' ')){
            const char separator=text[at++];had_time=true;size_t start=at;
            if(!digits(text,end,at,1,2,p.hour))return false;
            const bool full_hour=at-start==2;
            if(at==end||text[at++]!=':')return false;
            start=at;if(!digits(text,end,at,1,2,p.minute))return false;
            const bool full_minute=at-start==2;
            bool full_second=false;
            if(at<end&&text[at]==':'){++at;start=at;if(!digits(text,end,at,1,2,p.second))return false;full_second=at-start==2;}
            if(at<end&&text[at]=='.'){
                ++at;double extended_fraction=0,place=0.1;
                while(at<end&&text[at]>='0'&&text[at]<='9'){
                    const unsigned int digit=static_cast<unsigned int>(text[at++]-'0');
                    if(fraction_digits<7)p.fraction=p.fraction*10+digit;
                    extended_fraction+=digit*place;place*=0.1;
                    ++fraction_digits;
                }
                for(unsigned int i=fraction_digits;i<7;++i)p.fraction*=10;
                if(fraction_digits>7){

                    const double scaled=extended_fraction*10000000.0;
                    unsigned int rounded=static_cast<unsigned int>(scaled);const double remainder=scaled-rounded;
                    if(remainder>0.5||(remainder==0.5&&(rounded&1)))++rounded;
                    p.fraction=rounded;
                }
                if(p.hour==24&&(!fraction_digits||fraction_digits>7))return false;
            }
            strict_iso=begin==0&&end==size&&separator=='T'&&full_hour&&full_minute&&full_second&&fraction_digits<=7;
        }
        int zone_offset=0;bool utc=false,localized=false;
        if(at<end&&(text[at]=='Z'||text[at]=='z')){utc=true;++at;}
        else if(at<end&&(text[at]=='+'||text[at]=='-')){
            const bool negative=text[at++]=='-';size_t start=at;unsigned int raw=0,hour=0,minute=0;
            if(!digits(text,end,at,1,4,raw))return false;
            const size_t count=at-start;
            if(at<end&&text[at]==':'){if(count>2)return false;hour=raw;++at;if(!digits(text,end,at,strict_iso?0:1,2,minute))return false;}
            else if(count<=2)hour=raw;else{hour=raw/100;minute=raw%100;}
            if(hour>(strict_iso?99U:14U)||minute>(strict_iso?99U:59U))return false;
            zone_offset=static_cast<int>(hour*60+minute)*(negative?-1:1);localized=true;
        }
        if(at!=end||((utc||localized)&&!had_time))return false;
        int64_t value=0;if(!ticks(p,value))return false;
        int offset=0;if(localized&&!local(value-static_cast<int64_t>(zone_offset)*minute_ticks,value,offset))return false;
        format(value,utc,localized,offset,output);return true;
    }
};
