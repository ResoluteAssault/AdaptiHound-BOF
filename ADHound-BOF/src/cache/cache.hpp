#pragma once
#include <new>
#include "cache_encoding.hpp"
#include "cache_datetime.hpp"
static bool ah_random_bytes(unsigned char *,size_t);

enum ah_cache_map : unsigned int { AH_CACHE_GC, AH_CACHE_TYPE, AH_CACHE_MACHINE, AH_CACHE_DOMAIN, AH_CACHE_VALUE, AH_CACHE_DN, AH_CACHE_HOST, AH_CACHE_UNRESOLVED };
static const char *ah_cache_label(unsigned int value) {
    static const char *labels[] = {"Base","User","Computer","Group","ADLocalGroup","ADLocalUser","GPO","Domain","OU","Container","Configuration","CertTemplate","RootCA","AIACA","EnterpriseCA","NTAuthStore","IssuancePolicy","Site","SiteServer","SiteSubnet"};
    return value < sizeof(labels)/sizeof(labels[0]) ? labels[value] : nullptr;
}
static bool ah_cache_label_value(const char *kind,unsigned int &value) {
    for(value=0;value<20;++value) if(ah_eq(kind,ah_cache_label(value)))return true;
    return false;
}
static bool ah_cache_exact(const char *a,const char *b,size_t a_size,size_t b_size) {
    if(!a||!b)return a==b;
    if(a_size!=b_size)return false;
    for(size_t i=0;i<a_size;++i)if(a[i]!=b[i])return false;
    return true;
}
[[maybe_unused]] static bool ah_cache_exact(const char *a,const char *b){return ah_cache_exact(a,b,ah_len(a),ah_len(b));}
struct ah_cache_text { const char *data; size_t size; };
struct ah_cache_string { const char *value; ah_cache_string *next; size_t size=SIZE_MAX; };
static size_t ah_cache_string_size(const ah_cache_string &value){return value.size==SIZE_MAX?ah_len(value.value):value.size;}
struct ah_cache_entry { const char *key,*value; ah_cache_string *values; unsigned int map; int32_t label; bool null_values; ah_cache_entry *next,*bucket_next; size_t key_size,value_size; };
static const char *ah_cache_c_string(const ah_cache_entry *entry){

    return entry&&entry->value&&entry->value_size==ah_len(entry->value)?entry->value:nullptr;
}
class ah_cache_data final {
    size_t maximum;
    CRITICAL_SECTION mutex={};
    bool initialized=false;
    ah_cache_entry **buckets=nullptr,*first=nullptr,*last=nullptr;
    size_t bucket_count=0,entry_count=0;
    struct guard { ah_cache_data &owner; explicit guard(ah_cache_data &value):owner(value){if(owner.initialized)KERNEL32$EnterCriticalSection(&owner.mutex);}~guard(){if(owner.initialized)KERNEL32$LeaveCriticalSection(&owner.mutex);} };
    static size_t hash(unsigned int map,const char *key,size_t size) {uint64_t h=1469598103934665603ULL^map;for(size_t i=0;i<size;++i){h^=static_cast<unsigned char>(key[i]);h*=1099511628211ULL;}return static_cast<size_t>(h);}

    bool grow(){
        if(bucket_count&&entry_count<bucket_count-bucket_count/4)return true;
        if(bucket_count>SIZE_MAX/2){exhausted=true;return false;}
        size_t capacity=bucket_count?bucket_count*2:64;
        if(capacity>SIZE_MAX/sizeof(ah_cache_entry *)||capacity*sizeof(ah_cache_entry *)>maximum){exhausted=true;return false;}
        auto **replacement=ah_alloc<ah_cache_entry *>(capacity*sizeof(ah_cache_entry *));
        if(!replacement){exhausted=true;return false;}
        for(auto *item=first;item;item=item->next){size_t bucket=hash(item->map,item->key,item->key_size)&(capacity-1);item->bucket_next=replacement[bucket];replacement[bucket]=item;}
        ah_free(buckets);buckets=replacement;bucket_count=capacity;return true;
    }
public:
    ah_arena arena;
    const char *creation_date=nullptr,*creation_version=nullptr;
    bool exhausted=false;
    explicit ah_cache_data(size_t limit):maximum(limit?limit:SIZE_MAX),arena(limit){initialized=KERNEL32$InitializeCriticalSectionAndSpinCount(&mutex,4000)!=0;reset();}
    ~ah_cache_data(){ah_free(buckets);if(initialized)KERNEL32$DeleteCriticalSection(&mutex);}
    bool valid()const{return initialized&&buckets&&!arena.failed;}
    size_t limit()const{return maximum;}
    size_t entries(){guard locked(*this);return entry_count;}
    size_t buckets_count(){guard locked(*this);return bucket_count;}
    void reset(){
        ah_free(buckets);buckets=nullptr;bucket_count=entry_count=0;
        arena.reset();first=last=nullptr;exhausted=false;
        if(!grow())return;
        creation_version=arena.copy("1.0.0");char stamp[16];
        if(ah_output_timestamp(stamp)){char date[]={stamp[0],stamp[1],stamp[2],stamp[3],'-',stamp[4],stamp[5],'-',stamp[6],stamp[7],'T','0','0',':','0','0',':','0','0',0};creation_date=arena.copy(date);}else creation_date=arena.copy("0001-01-01T00:00:00");
    }
    const ah_cache_entry *get(unsigned int map,const char *key,size_t size=SIZE_MAX){
        guard locked(*this);
        if(!key||!buckets)return nullptr;
        if(size==SIZE_MAX)size=ah_len(key);
        for(auto *p=buckets[hash(map,key,size)&(bucket_count-1)];p;p=p->bucket_next)if(p->map==map&&ah_cache_exact(p->key,key,p->key_size,size))return p;
        return nullptr;
    }
    void clear(unsigned int map){
        guard locked(*this);
        ah_cache_entry **link=&first;last=nullptr;
        while(*link){
            auto *item=*link;
            if(item->map==map){*link=item->next;--entry_count;}
            else{last=item;link=&item->next;}
        }

        for(size_t i=0;i<bucket_count;++i)buckets[i]=nullptr;
        for(auto *item=first;item;item=item->next){size_t bucket=hash(item->map,item->key,item->key_size)&(bucket_count-1);item->bucket_next=buckets[bucket];buckets[bucket]=item;}
    }
    bool put(unsigned int map,const char *key,const char *value,int32_t label=0,ah_cache_string *values=nullptr,bool borrowed=false,bool replace=false,bool null_values=false){
        return put_sized(map,{key,ah_len(key)},{value,ah_len(value)},label,values,borrowed,replace,null_values);
    }
    bool put_sized(unsigned int map,ah_cache_text key,ah_cache_text value,int32_t label=0,ah_cache_string *values=nullptr,bool borrowed=false,bool replace=false,bool null_values=false){
        guard locked(*this);if(!key.data||!buckets||key.size==SIZE_MAX||value.size==SIZE_MAX||(!value.data&&value.size))return false;size_t bucket=hash(map,key.data,key.size)&(bucket_count-1);
        ah_cache_entry *existing=nullptr;for(auto *p=buckets[bucket];p;p=p->bucket_next)if(p->map==map&&ah_cache_exact(p->key,key.data,p->key_size,key.size)){existing=p;break;}
        if(existing&&!replace)return true;
        if(arena.failed){exhausted=true;return false;}
        if(!existing){if(!grow())return false;bucket=hash(map,key.data,key.size)&(bucket_count-1);}
        const char *stored_key=borrowed?key.data:arena.copy(key.data,key.size),*stored_value=borrowed||!value.data?value.data:arena.copy(value.data,value.size);
        ah_cache_string *stored_values=borrowed?values:nullptr,**tail=&stored_values;
        if(!borrowed)for(auto *p=values;p;p=p->next){auto *item=arena.make<ah_cache_string>();if(!item)break;item->size=ah_cache_string_size(*p);item->value=p->value?arena.copy(p->value,item->size):nullptr;*tail=item;tail=&item->next;}
        auto *entry=existing?existing:arena.make<ah_cache_entry>();
        if(!entry||!stored_key||(value.data&&!stored_value)||arena.failed){exhausted=true;return false;}
        entry->key=stored_key;entry->key_size=key.size;entry->value=stored_value;entry->value_size=value.size;entry->map=map;entry->label=label;entry->values=stored_values;entry->null_values=null_values;
        if(!existing){entry->bucket_next=buckets[bucket];buckets[bucket]=entry;if(last)last->next=entry;else first=entry;last=entry;++entry_count;}
        return true;
    }
    bool write(ah_buffer &out){
        guard locked(*this);const char *maps[]={"GlobalCatalogCache","IdToTypeCache","MachineSidCache","SIDToDomainCache","ValueToIdCache"};
        AH_TEXT(&out,"{");
        for(unsigned int map=0;map<5;++map){if(map)AH_TEXT(&out,",");ah_string(out,maps[map]);AH_TEXT(&out,":{");bool comma=false;
            for(auto *p=first;p;p=p->next)if(p->map==map){if(comma)AH_TEXT(&out,",");comma=true;ah_json_bytes(&out,p->key,p->key_size);AH_TEXT(&out,":");
                if(map==AH_CACHE_GC){if(p->null_values)AH_TEXT(&out,"null");else{AH_TEXT(&out,"[");bool more=false;for(auto *v=p->values;v;v=v->next){if(more)AH_TEXT(&out,",");more=true;if(v->value)ah_json_bytes(&out,v->value,ah_cache_string_size(*v));else AH_TEXT(&out,"null");}AH_TEXT(&out,"]");}}
                else if(map==AH_CACHE_TYPE)ah_int64(out,p->label);
                else if(p->value)ah_json_bytes(&out,p->value,p->value_size);else AH_TEXT(&out,"null");
            }AH_TEXT(&out,"}");
        }
        AH_TEXT(&out,",\"CacheCreationDate\":");if(creation_date)ah_string(out,creation_date);else AH_TEXT(&out,"null");
        AH_TEXT(&out,",\"CacheCreationVersion\":");if(creation_version)ah_string(out,creation_version);else AH_TEXT(&out,"null");AH_TEXT(&out,"}");return !out.failed;
    }
    ah_cache_data(const ah_cache_data&)=delete;ah_cache_data &operator=(const ah_cache_data&)=delete;
};

class ah_cache_json final {
    ah_cache_data &cache;
    const unsigned char *cursor,*end;
    bool failed=false;
    void space(){
        for(;;){
            while(cursor<end&&(*cursor==' '||*cursor=='\t'||*cursor=='\n'||*cursor=='\r'))++cursor;
            if(end-cursor<2||cursor[0]!='/')return;
            if(cursor[1]=='/'){
                cursor+=2;while(cursor<end&&*cursor!='\n'&&*cursor!='\r')++cursor;
            }else if(cursor[1]=='*'){
                cursor+=2;while(end-cursor>=2&&(cursor[0]!='*'||cursor[1]!='/'))++cursor;
                if(end-cursor<2){cursor=end;failed=true;return;}
                cursor+=2;
            }else return;
        }
    }
    bool take(unsigned char c){space();if(failed||cursor==end||*cursor!=c)return false;++cursor;return true;}
    bool word(const char *text){space();if(failed)return false;const unsigned char *p=cursor;for(;*text;++text)if(p==end||*p++!=static_cast<unsigned char>(*text))return false;cursor=p;return true;}
    bool quoted()const{return cursor<end&&(*cursor=='"'||*cursor=='\'');}
    static int hex(unsigned char c){return c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:c>='A'&&c<='F'?c-'A'+10:-1;}
    bool unit(unsigned int &value){value=0;for(unsigned int i=0;i<4;++i){if(cursor==end)return false;int n=hex(*cursor++);if(n<0)return false;value=(value<<4)|static_cast<unsigned int>(n);}return true;}
    static void utf8(ah_buffer &out,unsigned int c){char bytes[4];size_t n;if(c<0x80){bytes[0]=static_cast<char>(c);n=1;}else if(c<0x800){bytes[0]=static_cast<char>(0xc0|(c>>6));bytes[1]=static_cast<char>(0x80|(c&63));n=2;}else if(c<0x10000){bytes[0]=static_cast<char>(0xe0|(c>>12));bytes[1]=static_cast<char>(0x80|((c>>6)&63));bytes[2]=static_cast<char>(0x80|(c&63));n=3;}else{bytes[0]=static_cast<char>(0xf0|(c>>18));bytes[1]=static_cast<char>(0x80|((c>>12)&63));bytes[2]=static_cast<char>(0x80|((c>>6)&63));bytes[3]=static_cast<char>(0x80|(c&63));n=4;}ah_append(&out,bytes,n);}
    char *string(size_t *size=nullptr){
        space();if(failed||!quoted()){failed=true;return nullptr;}const unsigned char quote=*cursor++;ah_buffer out(cache.limit());bool closed=false;
        while(cursor<end){unsigned char c=*cursor++;if(c==quote){closed=true;break;}
            if(c!='\\'){ah_append(&out,reinterpret_cast<const char *>(&c),1);continue;}
            if(cursor==end){failed=true;return nullptr;}c=*cursor++;char decoded=0;
            if(c=='"'||c=='\''||c=='\\'||c=='/')decoded=static_cast<char>(c);else if(c=='b')decoded='\b';else if(c=='f')decoded='\f';else if(c=='n')decoded='\n';else if(c=='r')decoded='\r';else if(c=='t')decoded='\t';else if(c=='u'){
                unsigned int value=0;if(!unit(value)){failed=true;return nullptr;}
                while(value>=0xd800&&value<=0xdbff){
                    if(end-cursor<2||cursor[0]!='\\'||cursor[1]!='u'){value=0xfffd;break;}
                    cursor+=2;unsigned int low=0;if(!unit(low)){failed=true;return nullptr;}
                    if(low>=0xdc00&&low<=0xdfff){value=0x10000+((value-0xd800)<<10)+low-0xdc00;break;}

                    utf8(out,0xfffd);value=low;
                }
                if(value>=0xdc00&&value<=0xdfff)value=0xfffd;
                utf8(out,value);continue;
            }else{failed=true;return nullptr;}ah_append(&out,&decoded,1);
        }
        if(!closed||out.failed||out.length>INT32_MAX||(out.length&&!KERNEL32$MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,out.data,static_cast<int>(out.length),nullptr,0))){failed=true;return nullptr;}
        if(size)*size=out.length;
        char *result=cache.arena.copy(out.data,out.length);if(!result)failed=true;return result;
    }
    char *property(size_t *size=nullptr){
        space();if(failed)return nullptr;
        if(quoted())return string(size);
        const auto *begin=cursor;

        while(cursor<end&&((*cursor>='a'&&*cursor<='z')||(*cursor>='A'&&*cursor<='Z')||(*cursor>='0'&&*cursor<='9')||*cursor=='_'||*cursor=='$'))++cursor;
        if(cursor==begin)return nullptr;
        if(size)*size=static_cast<size_t>(cursor-begin);
        char *name=cache.arena.copy(reinterpret_cast<const char *>(begin),static_cast<size_t>(cursor-begin));
        if(!name)failed=true;
        return name;
    }
    bool colon(){

        while(cursor<end&&(*cursor==' '||*cursor=='\t'||*cursor=='\n'||*cursor=='\r'))++cursor;
        if(cursor==end||*cursor!=':')return false;
        ++cursor;return true;
    }
    bool number(bool *integer=nullptr){
        space();if(cursor<end&&*cursor=='-')++cursor;
        if(cursor==end)return false;
        if(*cursor=='0')++cursor;else{if(*cursor<'1'||*cursor>'9')return false;while(cursor<end&&*cursor>='0'&&*cursor<='9')++cursor;}
        bool whole=true;if(cursor<end&&*cursor=='.'){whole=false;++cursor;const auto *digits=cursor;while(cursor<end&&*cursor>='0'&&*cursor<='9')++cursor;if(cursor==digits)return false;}
        if(cursor<end&&(*cursor=='e'||*cursor=='E')){whole=false;++cursor;if(cursor<end&&(*cursor=='+'||*cursor=='-'))++cursor;const auto *digits=cursor;while(cursor<end&&*cursor>='0'&&*cursor<='9')++cursor;if(cursor==digits)return false;}
        if(integer)*integer=whole;
        return true;
    }
    bool scalar_string(const char *&value,size_t *size=nullptr){
        space();if(cursor==end)return false;
        value=nullptr;if(size)*size=0;
        if(quoted()){value=string(size);return value!=nullptr;}
        if(word("null"))return true;
        const auto *begin=cursor;

        if(!word("true")&&!word("false")&&!number())return false;
        if(size)*size=static_cast<size_t>(cursor-begin);
        value=cache.arena.copy(reinterpret_cast<const char *>(begin),static_cast<size_t>(cursor-begin));
        return value!=nullptr;
    }
    bool label(int32_t &value){
        space();if(cursor==end)return false;
        if(quoted()){
            size_t size=0;const char *name=string(&size);if(!name||size!=ah_len(name))return false;
            name=ah_trim_text(cache.arena,name);if(!name)return false;
            int64_t numeric=0;
            if(ah_try_int64_text(name,numeric)){
                if(numeric<INT32_MIN||numeric>INT32_MAX)return false;
                value=static_cast<int32_t>(numeric);return true;
            }
            uint32_t combined=0;
            for(;;){
                const char *end_name=name;while(*end_name&&*end_name!=',')++end_name;
                const char *part=cache.arena.copy(name,static_cast<size_t>(end_name-name));
                part=part?ah_trim_text(cache.arena,part):nullptr;
                unsigned int kind=0;if(!part||!ah_cache_label_value(part,kind))return false;
                combined|=kind;
                if(!*end_name)break;
                name=end_name+1;
            }
            value=static_cast<int32_t>(combined);return true;
        }
        if(word("true")){value=1;return true;}
        if(word("false")){value=0;return true;}
        const auto *begin=cursor;bool integer=false;
        if(!number(&integer)||!integer)return false;
        const char *text=cache.arena.copy(reinterpret_cast<const char *>(begin),static_cast<size_t>(cursor-begin));int64_t numeric=0;
        if(!text||!ah_try_int64_text(text,numeric))return false;

        const uint32_t bits=static_cast<uint32_t>(numeric);
        value=static_cast<int32_t>(bits<=INT32_MAX?static_cast<int64_t>(bits):static_cast<int64_t>(bits)-4294967296LL);
        return true;
    }
    bool skip(unsigned int depth){
        if(depth>64)return false;
        space();if(cursor==end)return false;
        if(quoted())return string()!=nullptr;
        if(*cursor=='{'){++cursor;if(take('}'))return true;for(;;){if(!property()||!colon()||!skip(depth+1))return false;if(take('}'))return true;if(!take(','))return false;if(take('}'))return true;}}
        if(*cursor=='['){++cursor;if(take(']'))return true;for(;;){if(!skip(depth+1))return false;if(take(']'))return true;if(!take(','))return false;if(take(']'))return true;}}
        return word("null")||word("true")||word("false")||number();
    }
    bool dictionary(unsigned int map){
        if(word("null")){cache.clear(map);return true;}
        if(!take('{'))return false;
        if(take('}'))return true;
        for(;;){size_t key_size=0,value_size=0;char *key=property(&key_size);if(!key||!colon())return false;const char *value=nullptr;int32_t kind=0;bool null_values=false;ah_cache_string *values=nullptr,**tail=&values;
            if(map==AH_CACHE_GC){null_values=word("null");if(!null_values){if(!take('['))return false;if(!take(']')){do{const char *item=nullptr;size_t size=0;if(!scalar_string(item,&size))return false;auto *node=cache.arena.make<ah_cache_string>();if(!node)return false;node->value=item;node->size=size;*tail=node;tail=&node->next;if(take(']'))break;if(!take(','))return false;if(take(']'))break;}while(true);}}}
            else if(map==AH_CACHE_TYPE){if(!label(kind))return false;}
            else if(!scalar_string(value,&value_size))return false;
            if(!cache.put_sized(map,{key,key_size},{value,value_size},kind,values,true,true,null_values))return false;
            if(take('}'))return true;
            if(!take(','))return false;
            if(take('}'))return true;
        }
    }
    const char *version(const char *text,size_t size){
        ah_buffer normalized(cache.limit(),64);size_t offset=0,parts=0;
        auto whitespace=[](unsigned char c){return c==' '||(c>=9&&c<=13);};
        for(;;){
            if(parts==4)return nullptr;
            size_t end_part=offset;while(end_part<size&&text[end_part]!='.')++end_part;
            while(offset<end_part&&whitespace(static_cast<unsigned char>(text[offset])))++offset;
            bool negative=false;if(offset<end_part&&(text[offset]=='+'||text[offset]=='-'))negative=text[offset++]=='-';
            const size_t digits=offset;uint32_t value=0;
            while(offset<end_part&&text[offset]>='0'&&text[offset]<='9'){
                unsigned int digit=static_cast<unsigned int>(text[offset++]-'0');
                if(value>(static_cast<uint32_t>(INT32_MAX)-digit)/10)return nullptr;
                value=value*10+digit;
            }
            if(offset==digits||(negative&&value))return nullptr;
            while(offset<end_part&&whitespace(static_cast<unsigned char>(text[offset])))++offset;

            while(offset<end_part&&text[offset]==0)++offset;
            if(offset!=end_part)return nullptr;
            if(parts++)AH_TEXT(&normalized,".");
            char digits_buffer[16];const char *number=ah_decimal(digits_buffer+sizeof(digits_buffer),value);ah_append(&normalized,number,ah_len(number));
            if(end_part==size)break;
            offset=end_part+1;
        }
        return parts>=2&&!normalized.failed?cache.arena.copy(normalized.data,normalized.length):nullptr;
    }
public:
    ah_cache_json(ah_cache_data &value,const char *data,size_t length):cache(value),cursor(reinterpret_cast<const unsigned char *>(data)),end(cursor+length){}
    bool parse(bool allow_bom=true){
        if(!cache.valid())return false;
        if(allow_bom&&end-cursor>=3&&cursor[0]==0xef&&cursor[1]==0xbb&&cursor[2]==0xbf)cursor+=3;
        space();if(cursor==end)return !failed&&!cache.arena.failed;
        if(word("null")){space();return !failed&&!cache.arena.failed&&cursor==end;}
        if(!take('{'))return false;
        if(!take('}'))do{size_t key_size=0;char *key=property(&key_size);if(!key||!colon())return false;int map=-1;
            const bool c_string=key_size==ah_len(key);
            const char *names[]={"GlobalCatalogCache","IdToTypeCache","MachineSidCache","SIDToDomainCache","ValueToIdCache"};for(int i=0;i<5;++i)if(c_string&&ah_eq(key,names[i]))map=i;
            if(map>=0){if(!dictionary(static_cast<unsigned int>(map)))return false;}
            else if(c_string&&(ah_eq(key,"CacheCreationDate")||ah_eq(key,"CacheCreationVersion"))){
                const bool date=ah_eq(key,"CacheCreationDate");const char *value=nullptr;
                if(word("null")){if(date)return false;}
                else{size_t size=0;value=string(&size);if(!value)return false;if(date){char normalized[64];if(!ah_cache_datetime::parse(value,size,normalized))return false;value=cache.arena.copy(normalized);if(!value)return false;}else{value=version(value,size);if(!value)return false;}}
                if(date)cache.creation_date=value;else cache.creation_version=value;
            }
            else if(!skip(0))return false;
            if(take('}'))break;
            if(!take(','))return false;
            if(take('}'))break;
        }while(true);
        space();return !failed&&!cache.arena.failed&&cursor==end;
    }
};

static ah_cache_data *ah_current_cache=nullptr;
static const char *ah_cached_machine_sid(const char *computer){auto *entry=ah_current_cache?ah_current_cache->get(AH_CACHE_MACHINE,computer):nullptr;return ah_cache_c_string(entry);}
static void ah_cache_machine_sid(const char *computer,const char *sid){if(ah_current_cache&&computer&&sid)ah_current_cache->put(AH_CACHE_MACHINE,computer,sid);}
static bool ah_cache_type(const char *id,const char **kind){auto *entry=ah_current_cache?ah_current_cache->get(AH_CACHE_TYPE,id):nullptr;if(!entry)return false;*kind=ah_cache_label(entry->label);return *kind!=nullptr;}
static void ah_cache_add_type(const char *id,const char *kind){unsigned int value=0;if(ah_current_cache&&id&&kind&&ah_cache_label_value(kind,value))ah_current_cache->put(AH_CACHE_TYPE,id,nullptr,value);}
static bool ah_cache_domain(const char *key,const char **value){auto *entry=ah_current_cache?ah_current_cache->get(AH_CACHE_DOMAIN,key):nullptr;const char *text=ah_cache_c_string(entry);if(!text)return false;*value=text;return true;}
static void ah_cache_add_domain(const char *key,const char *value){if(ah_current_cache&&key&&value)ah_current_cache->put(AH_CACHE_DOMAIN,key,value);}
static bool ah_cache_typed(unsigned int map,const char *key,const char **id,const char **kind){auto *entry=ah_current_cache?ah_current_cache->get(map,key):nullptr;if(!entry||(entry->value&&!ah_cache_c_string(entry)))return false;*id=entry->value;*kind=ah_cache_label(entry->label);return true;}
static void ah_cache_add_typed(unsigned int map,const char *key,const char *id,const char *kind){unsigned int value=0;if(ah_current_cache&&key&&(!kind||ah_cache_label_value(kind,value)))ah_current_cache->put(map,key,id,value);}
static bool ah_cached_host_sid(const char *host,const char **sid){if(!ah_current_cache)return false;
    ah_arena names(131072);char *key=ah_upper(names,host);auto *entry=key?ah_current_cache->get(AH_CACHE_HOST,key):nullptr;if(!entry||(entry->value&&!ah_cache_c_string(entry)))return false;*sid=entry->value;return true;}
static void ah_cache_host_sid(const char *host,const char *sid){if(ah_current_cache){ah_arena names(131072);char *key=ah_upper(names,host);if(key)ah_current_cache->put(AH_CACHE_HOST,key,sid);}}

static bool ah_cached_account(const char *name,const char *domain,const char **id,const char **kind){
    if(!ah_current_cache)return false;
    ah_arena names(131072);char *key=ah_concat(names,name,"|",domain);
    auto *entry=key?ah_current_cache->get(AH_CACHE_VALUE,key):nullptr;
    if(!ah_cache_c_string(entry)||!ah_cache_type(entry->value,kind))return false;
    *id=entry->value;return true;
}
static void ah_cache_account(const char *name,const char *domain,const char *id,const char *kind){
    if(!ah_current_cache||!id)return;
    ah_arena names(131072);char *key=ah_concat(names,name,"|",domain);
    if(key){ah_current_cache->put(AH_CACHE_VALUE,key,id);}
    ah_cache_add_type(id,kind);
}
static const ah_cache_entry *ah_cached_gc(const char *name){
    if(!ah_current_cache)return nullptr;
    wchar_t *wide=ah_wide(name);if(!wide)return nullptr;
    int count=KERNEL32$LCMapStringW(LOCALE_USER_DEFAULT,LCMAP_UPPERCASE,wide,-1,nullptr,0);
    wchar_t *upper=count>0?ah_alloc<wchar_t>(static_cast<size_t>(count)*sizeof(wchar_t)):nullptr;
    ah_arena names(131072);const char *key=upper&&KERNEL32$LCMapStringW(LOCALE_USER_DEFAULT,LCMAP_UPPERCASE,wide,-1,upper,count)?names.utf8(upper):nullptr;
    const auto *entry=key?ah_current_cache->get(AH_CACHE_GC,key):nullptr;ah_free(upper);ah_free(wide);
    for(auto *item=entry?entry->values:nullptr;item;item=item->next)if(item->value&&ah_cache_string_size(*item)!=ah_len(item->value))return nullptr;
    return entry;
}
static void ah_cache_gc(const char *name,ah_session_info *matches){
    if(!ah_current_cache)return;
    ah_arena copy(ah_current_cache->limit());ah_cache_string *values=nullptr,**tail=&values;
    for(auto *p=matches;p;p=p->next){auto *item=copy.make<ah_cache_string>();if(!item)return;item->value=p->sid;item->size=ah_len(p->sid);*tail=item;tail=&item->next;}
    ah_current_cache->put(AH_CACHE_GC,name,nullptr,0,values);
}
static bool ah_cached_dn(const char *dn,const char **id,const char **kind){
    if(!ah_current_cache)return false;
    ah_arena names(131072);char *key=ah_upper(names,dn);return key&&ah_cache_typed(AH_CACHE_DN,key,id,kind);
}
static void ah_cache_dn(const char *dn,const char *id,const char *kind){
    if(ah_current_cache){ah_arena names(131072);char *key=ah_upper(names,dn);if(key)ah_cache_add_typed(AH_CACHE_DN,key,id,kind);}
}
static bool ah_cached_unresolved(const char *id){return ah_current_cache&&ah_current_cache->get(AH_CACHE_UNRESOLVED,id);}
static void ah_cache_unresolved(const char *id){if(ah_current_cache)ah_current_cache->put(AH_CACHE_UNRESOLVED,id,nullptr);}

class ah_cache_scope final {
    ah_cache_data data;
    ah_cache_data *previous=nullptr;
    char *path=nullptr;
    bool enabled=false,requested=false,memory_only=true,file_failed=false,finished=false,finish_result=true;
    static char *default_name(){
        ah_arena names(131072);wchar_t *machine=nullptr;HKEY key=nullptr;
        if(ADVAPI32$RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Cryptography",0,KEY_QUERY_VALUE|KEY_WOW64_64KEY,&key)==ERROR_SUCCESS){DWORD type=0,size=0;if(ADVAPI32$RegQueryValueExW(key,L"MachineGuid",nullptr,&type,nullptr,&size)==ERROR_SUCCESS&&type==REG_SZ&&size>=sizeof(wchar_t)&&size<=65536){machine=ah_alloc<wchar_t>(size+sizeof(wchar_t));if(machine&&ADVAPI32$RegQueryValueExW(key,L"MachineGuid",nullptr,&type,reinterpret_cast<LPBYTE>(machine),&size)!=ERROR_SUCCESS){ah_free(machine);machine=nullptr;}}ADVAPI32$RegCloseKey(key);}
        const char *identifier=machine&&*machine?names.utf8(machine):nullptr;ah_free(machine);
        if(!identifier){ah_native_library kernel(L"kernel32.dll");auto query=kernel.find<decltype(&GetComputerNameW)>("GetComputerNameW");wchar_t name[MAX_COMPUTERNAME_LENGTH+1]={};DWORD size=MAX_COMPUTERNAME_LENGTH+1;if(query&&query(name,&size))identifier=names.utf8(name);}
        if(!identifier)return nullptr;
        ah_native_library kernel(L"kernel32.dll");auto query=kernel.find<decltype(&GetTempPathW)>("GetTempPathW");
        DWORD capacity=query?query(0,nullptr):0;
        if(!capacity||capacity>32768)return nullptr;
        wchar_t *temporary=ah_alloc<wchar_t>((static_cast<size_t>(capacity)+1)*sizeof(wchar_t));
        DWORD length=temporary?query(capacity,temporary):0;
        const char *directory=length&&length<capacity?names.utf8(temporary):nullptr;ah_free(temporary);
        if(!directory||!*directory)return nullptr;
        char *base64=ah_base64_encode(reinterpret_cast<const unsigned char *>(identifier),ah_len(identifier));
        if(base64)for(char *p=base64;*p;++p){if(*p=='/')*p='_';else if(*p=='+')*p='-';}
        const char *filename=base64?ah_concat(names,base64,".bin"):nullptr;
        char *result=filename?ah_heap_copy(ah_concat(names,directory,filename)):nullptr;ah_free(base64);return result;
    }
    bool load(){
        wchar_t *name=ah_wide(path);HANDLE file=name?KERNEL32$CreateFileW(name,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr):INVALID_HANDLE_VALUE;ah_free(name);
        if(file==INVALID_HANDLE_VALUE)return false;
        LARGE_INTEGER size={};bool ok=KERNEL32$GetFileSizeEx(file,&size)&&size.QuadPart>=0&&static_cast<uint64_t>(size.QuadPart)<=data.limit();
        size_t length=ok?static_cast<size_t>(size.QuadPart):0,allocation=0;
        ok=ok&&ah_size_add(length,2,allocation);
        char *bytes=ok?ah_alloc(allocation):nullptr;size_t offset=0;
        while(bytes&&offset<length){DWORD read=0,wanted=static_cast<DWORD>(length-offset>1048576?1048576:length-offset);if(!KERNEL32$ReadFile(file,bytes+offset,wanted,&read,nullptr)||!read){ok=false;break;}offset+=read;}
        KERNEL32$CloseHandle(file);ok=ok&&bytes&&offset==length;
        if(ok)ok=ah_cache_decode_file(bytes,length,data.limit());
        if(ok){data.creation_date=data.arena.copy("0001-01-01T00:00:00");data.creation_version=nullptr;ah_cache_json json(data,bytes,length);ok=json.parse(false);}ah_free(bytes);if(!ok)data.reset();return ok;
    }
    bool save(){
        ah_buffer bytes(data.limit());if(!data.write(bytes))return false;
        ah_native_library kernel(L"kernel32.dll");auto write=kernel.find<decltype(&WriteFile)>("WriteFile");auto flush=kernel.find<decltype(&FlushFileBuffers)>("FlushFileBuffers");auto move=kernel.find<decltype(&MoveFileExW)>("MoveFileExW");auto remove=kernel.find<decltype(&DeleteFileW)>("DeleteFileW");
        if(!write||!flush||!move||!remove)return false;
        ah_arena names(131072);wchar_t *destination=ah_wide(path),*temporary=nullptr;HANDLE file=INVALID_HANDLE_VALUE;
        for(unsigned int attempt=0;destination&&attempt<16;++attempt){unsigned char random[8];if(!ah_random_bytes(random,sizeof(random)))break;char suffix[17];const char hex[]="0123456789abcdef";for(unsigned int i=0;i<8;++i){suffix[2*i]=hex[random[i]>>4];suffix[2*i+1]=hex[random[i]&15];}suffix[16]=0;ah_free(temporary);temporary=ah_wide(ah_concat(names,ah_concat(names,path,".adaptihound-",suffix),".tmp"));if(!temporary)break;file=KERNEL32$CreateFileW(temporary,GENERIC_WRITE,FILE_SHARE_READ,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_WRITE_THROUGH,nullptr);if(file!=INVALID_HANDLE_VALUE)break;if(KERNEL32$GetLastError()!=ERROR_FILE_EXISTS&&KERNEL32$GetLastError()!=ERROR_ALREADY_EXISTS)break;}
        const bool created=file!=INVALID_HANDLE_VALUE;bool ok=created;size_t offset=0;
        while(ok&&offset<bytes.length){DWORD written=0,count=static_cast<DWORD>(bytes.length-offset>1048576?1048576:bytes.length-offset);if(!write(file,bytes.data+offset,count,&written,nullptr)||!written)ok=false;else offset+=written;}
        if(ok){ok=flush(file)!=0;}
        if(file!=INVALID_HANDLE_VALUE)KERNEL32$CloseHandle(file);
        if(ok)ok=move(temporary,destination,MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)!=0;
        if(!ok&&created&&temporary){remove(temporary);}
        ah_free(temporary);ah_free(destination);return ok;
    }
public:
    bool loaded=false;
    ah_cache_scope(const char *name,size_t limit,bool active,bool memcache,bool file_cache=false):data(limit),previous(ah_current_cache),enabled(active),requested(active),memory_only(!file_cache||memcache){
        ah_current_cache=nullptr;
        if(!enabled)return;
        if(!data.valid()){enabled=false;BeaconPrintf(CALLBACK_ERROR,"AdaptiHound: cannot initialize lookup cache");return;}
        ah_current_cache=&data;
        if(!file_cache&&!memcache){ah_log_telemetry("AdaptiHound: lookup cache uses RAM only");return;}
        path=name&&*name?ah_heap_copy(name):default_name();
        if(!path){file_failed=true;BeaconPrintf(CALLBACK_ERROR,"AdaptiHound: cannot resolve cache path; lookups remain in RAM");return;}
        loaded=load();ah_log_telemetry("AdaptiHound: cache %s: %s%s\n",path,loaded?"loaded":"fresh",memory_only?" (read-only file)":"");
    }
    ~ah_cache_scope(){ah_current_cache=previous;ah_free(path);}
    bool finish(){if(finished)return finish_result;finished=true;if(!enabled){finish_result=!requested;return finish_result;}if(data.exhausted)ah_log_telemetry("AdaptiHound: cache memory limit reached; additional lookups were not retained\n");if(file_failed){finish_result=false;return false;}if(memory_only)return true;bool ok=save();if(!ok)BeaconPrintf(CALLBACK_ERROR,"AdaptiHound: cannot atomically save cache %s\n",path);finish_result=ok;return ok;}
    const char *filename()const{return path;}
    ah_cache_scope(const ah_cache_scope&)=delete;ah_cache_scope &operator=(const ah_cache_scope&)=delete;
};
