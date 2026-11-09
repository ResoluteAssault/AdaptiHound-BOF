#pragma once
#include <new>
static void ah_csv_cell(ah_buffer &,const char *);
struct ah_json_slice {
    const char *begin=nullptr,*end=nullptr;
    size_t size() const {
        return static_cast<size_t>(end-begin);
    }
};
class ah_combined_json final {
    const char *at,*end;
    void space() {
        while(at<end&&(*at==' '||*at=='\t'||*at=='\r'||*at=='\n'))++at;
    }
    static bool hex(char c) {
        return(c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F');
    }
    public: explicit ah_combined_json(ah_json_slice s):at(s.begin),end(s.end) {
    }
    bool take(char c) {
        space();
        if(at==end||*at!=c)return false;
        ++at;
        return true;
    }
    bool done() {
        space();
        return at==end;
    }
    bool string(ah_json_slice &s) {
        space();
        s.begin=at;
        if(at==end||*at++!='"')return false;
        while(at<end) {
            unsigned char c=static_cast<unsigned char>(*at++);
            if(c=='"') {
                s.end=at;
                return true;
            }
            if(c<32)return false;
            if(c=='\\') {
                if(at==end)return false;
                char escaped=*at++;
                if(escaped=='u') {
                    for(int i=0; i<4; ++i)if(at==end||!hex(*at++))return false;
                }
                else if(escaped!='"'&&escaped!='\\'&&escaped!='/'&&escaped!='b'&&escaped!='f'&&escaped!='n'&&escaped!='r'&&escaped!='t')return false;
            }
        }
        return false;
    }
    bool value(ah_json_slice &s,unsigned int depth=0) {
        space();
        s.begin=at;
        if(at==end||depth>256)return false;
        if(*at=='"')return string(s);
        if(*at=='{'||*at=='[') {
            char close=*at++=='{'?'}':']';
            space();
            if(at<end&&*at==close) {
                ++at;
                s.end=at;
                return true;
            }
            for(;;) {
                ah_json_slice child;
                if(close=='}'&&(!string(child)||!take(':')))return false;
                if(!value(child,depth+1))return false;
                if(take(close)) {
                    s.end=at;
                    return true;
                }
                if(!take(','))return false;
            }
        }
        const char *literal=*at=='t'?"true":*at=='f'?"false":*at=='n'?"null":nullptr;
        if(literal) {
            for(; *literal; ++literal)if(at==end||*at++!=*literal)return false;
            s.end=at;
            return true;
        }
        if(*at=='-')++at;
        if(at==end||*at<'0'||*at>'9')return false;
        if(*at=='0')++at;
        else while(at<end&&*at>='0'&&*at<='9')++at;
        if(at<end&&*at=='.') {
            ++at;
            const char *start=at;
            while(at<end&&*at>='0'&&*at<='9')++at;
            if(at==start)return false;
        }
        if(at<end&&(*at=='e'||*at=='E')) {
            ++at;
            if(at<end&&(*at=='+'||*at=='-'))++at;
            const char *start=at;
            while(at<end&&*at>='0'&&*at<='9')++at;
            if(at==start)return false;
        }
        s.end=at;
        return true;
    }
    static bool member(ah_json_slice object,const char *name,ah_json_slice &out) {
        ah_combined_json p(object);
        if(!p.take('{'))return false;
        bool found=false;
        if(!p.take('}'))for(;;) {
            ah_json_slice key,value;
            if(!p.string(key)||!p.take(':')||!p.value(value))return false;
            size_t length=ah_len(name);
            if(key.size()==length+2) {
                bool match=true;
                for(size_t i=0; i<length; ++i)if(key.begin[i+1]!=name[i])match=false;
                if(match) {
                    if(found)return false;
                    out=value;
                    found=true;
                }
            }
            if(p.take('}'))break;
            if(!p.take(','))return false;
        }
        return p.done()&&found;
    }
    template<typename Consumer>static bool array(ah_json_slice source,Consumer consume) {
        ah_combined_json p(source);
        if(!p.take('['))return false;
        if(!p.take(']'))for(;;) {
            ah_json_slice item;
            if(!p.value(item)||!consume(item))return false;
            if(p.take(']'))break;
            if(!p.take(','))return false;
        }
        return p.done();
    }
};
class ah_combined_output final {
    public: struct domain_target {
        char *name,*sid;
        domain_target *next;
    };
    private: struct member {
        char *id,*body;
        size_t length;
        member *next,*bucket_next;
    };
    struct row {
        char *id,*body;
        size_t length;
        bool primary,enterprise;
        size_t members_start,members_end;
        member *members,*members_tail;
        member **member_buckets;
        size_t member_capacity,member_count;
        row *next,*bucket_next;
    };
    struct dataset {
        const char *name;
        row *head,*tail;
        row **buckets;
        size_t capacity,count;
    };
    struct context {
        char *dn;
        context *next;
    };
    struct file final {
        char *name=nullptr;
        bool csv=false;
        ah_buffer body;
        file *next=nullptr;
        explicit file(size_t maximum):body(maximum) {
        }
    };
    ah_arena arena;
    ah_directory support_directory;
    size_t maximum;
    int methods;
    bool invalid=false,finalized=false;
    dataset data[16]= {
    };
    context *contexts=nullptr;
    domain_target *targets=nullptr,*targets_tail=nullptr;
    ah_call_status *calls=nullptr,*calls_tail=nullptr;
    file *files=nullptr,*files_tail=nullptr;
    char timestamp[16]= {
    };
    static bool valid_utf8(ah_json_slice source) {
        const auto *at=reinterpret_cast<const unsigned char*>(source.begin),*end=reinterpret_cast<const unsigned char*>(source.end);
        while(at<end){
            unsigned char first=*at++;if(first<128)continue;
            size_t count=first>=0xc2&&first<=0xdf?1:first>=0xe0&&first<=0xef?2:first>=0xf0&&first<=0xf4?3:0;
            if(!count||static_cast<size_t>(end-at)<count)return false;
            if((first==0xe0&&*at<0xa0)||(first==0xed&&*at>=0xa0)||(first==0xf0&&*at<0x90)||(first==0xf4&&*at>=0x90))return false;
            for(size_t i=0;i<count;++i)if((at[i]&0xc0)!=0x80)return false;
            at+=count;
        }
        return true;
    }
    static uint64_t hash(const char *key) {
        uint64_t out=1469598103934665603ULL;
        while(*key) {
            out^=static_cast<unsigned char>(ah_lower(*key++));
            out*=1099511628211ULL;
        }
        return out;
    }
    bool fail() {
        invalid=true;
        return false;
    }
    static unsigned int unhex(char c) {
        return c>='0'&&c<='9'?static_cast<unsigned int>(c-'0'):c>='a'&&c<='f'?static_cast<unsigned int>(c-'a'+10):static_cast<unsigned int>(c-'A'+10);
    }
    char *text(ah_json_slice source,ah_arena *destination=nullptr) {
        if(source.size()<2||*source.begin!='"'||source.end[-1]!='"')return nullptr;
        if(source.size()==SIZE_MAX)return nullptr;
        ah_buffer value(source.size()+1,4096);
        for(const char *p=source.begin+1; p<source.end-1; ++p) {
            if(*p!='\\') {
                ah_append(&value,p,1);
                continue;
            }
            if(++p>=source.end-1)return nullptr;
            char c=*p;
            if(c=='u') {
                if(source.end-1-p<5)return nullptr;
                unsigned int code=0;
                for(int i=0; i<4; ++i)code=code*16+unhex(*++p);
                if(code>=0xd800&&code<=0xdbff) {
                    if(source.end-1-p<7||p[1]!='\\'||p[2]!='u')return nullptr;
                    p+=2;
                    unsigned int low=0;
                    for(int i=0; i<4; ++i)low=low*16+unhex(*++p);
                    if(low<0xdc00||low>0xdfff)return nullptr;
                    code=0x10000+((code-0xd800)<<10)+(low-0xdc00);
                }
                else if(code>=0xdc00&&code<=0xdfff)return nullptr;
                char encoded[4];
                size_t n=0;
                if(code<128)encoded[n++]=static_cast<char>(code);
                else if(code<0x800) {
                    encoded[n++]=static_cast<char>(0xc0|(code>>6));
                    encoded[n++]=static_cast<char>(0x80|(code&63));
                }
                else if(code<0x10000) {
                    encoded[n++]=static_cast<char>(0xe0|(code>>12));
                    encoded[n++]=static_cast<char>(0x80|((code>>6)&63));
                    encoded[n++]=static_cast<char>(0x80|(code&63));
                }
                else {
                    encoded[n++]=static_cast<char>(0xf0|(code>>18));
                    encoded[n++]=static_cast<char>(0x80|((code>>12)&63));
                    encoded[n++]=static_cast<char>(0x80|((code>>6)&63));
                    encoded[n++]=static_cast<char>(0x80|(code&63));
                }
                ah_append(&value,encoded,n);
            }
            else {
                if(c=='b')c='\b';
                else if(c=='f')c='\f';
                else if(c=='n')c='\n';
                else if(c=='r')c='\r';
                else if(c=='t')c='\t';
                ah_append(&value,&c,1);
            }
        }
        if(value.failed)return nullptr;
        char *result=(destination?*destination:arena).copy(value.data,value.length);
        if(!result||ah_len(result)!=value.length)return nullptr;
        return result;
    }
    bool number(ah_json_slice source,int64_t &out) {
        if(!source.begin||source.size()>24)return false;
        char value[25];
        for(size_t i=0; i<source.size(); ++i)value[i]=source.begin[i];
        value[source.size()]=0;
        return ah_try_int64_text(value,out);
    }
    bool grow(dataset &set) {
        if(set.capacity&&set.count<set.capacity-set.capacity/4)return true;
        size_t capacity=set.capacity?set.capacity*2:32;
        if(capacity<set.capacity||capacity>SIZE_MAX/sizeof(row*))return fail();
        row **buckets=ah_alloc<row*>(capacity*sizeof(row*));
        if(!buckets)return fail();
        for(row *item=set.head; item; item=item->next) {
            size_t slot=hash(item->id)&(capacity-1);
            item->bucket_next=buckets[slot];
            buckets[slot]=item;
        }
        ah_free(set.buckets);set.buckets=buckets;
        set.capacity=capacity;
        return true;
    }
    static char *copy_body(ah_json_slice value) {
        char *result=ah_alloc(value.size());
        if(result)for(size_t i=0;i<value.size();++i)result[i]=value.begin[i];
        return result;
    }
    void release_body(row &item) {
        ah_free(item.body);item.body=nullptr;
        for(member *entry=item.members;entry;entry=entry->next){ah_free(entry->body);entry->body=nullptr;}
        ah_free(item.member_buckets);item.member_buckets=nullptr;
        item.member_capacity=item.member_count=0;item.members=item.members_tail=nullptr;
    }
    bool grow_members(row &target) {
        if(target.member_capacity&&target.member_count<target.member_capacity-target.member_capacity/4)return true;
        size_t capacity=target.member_capacity?target.member_capacity*2:32;
        if(capacity<target.member_capacity||capacity>SIZE_MAX/sizeof(member*))return false;
        member **replacement=ah_alloc<member*>(capacity*sizeof(member*));
        if(!replacement)return false;
        for(member *item=target.members;item;item=item->next){size_t slot=hash(item->id)&(capacity-1);item->bucket_next=replacement[slot];replacement[slot]=item;}
        ah_free(target.member_buckets);target.member_buckets=replacement;target.member_capacity=capacity;return true;
    }
    bool members(row &target,ah_json_slice array) {
        ah_arena temporary(maximum,4096);
        return ah_combined_json::array(array,[&](ah_json_slice value) {
            temporary.reset();
            ah_json_slice id_slice,type_slice;
            if(!ah_combined_json::member(value,"ObjectIdentifier",id_slice)||!ah_combined_json::member(value,"ObjectType",type_slice))return false;
            const char *id=text(id_slice,&temporary),*type=text(type_slice,&temporary);
            if(!id||!*id||!type||!ah_eq(type,"Computer"))return false;
            if(target.member_capacity)for(member *old=target.member_buckets[hash(id)&(target.member_capacity-1)];old;old=old->bucket_next)if(ah_eq(id,old->id))return true;
            if(!grow_members(target))return false;
            member *item=arena.make<member>();if(!item)return false;
            item->id=arena.copy(id);item->body=copy_body(value);item->length=value.size();
            if(!item->id||!item->body){ah_free(item->body);item->body=nullptr;return false;}
            size_t slot=hash(id)&(target.member_capacity-1);item->bucket_next=target.member_buckets[slot];target.member_buckets[slot]=item;
            if(target.members_tail)target.members_tail->next=item;else target.members=item;
            target.members_tail=item;++target.member_count;return true;
        });
    }
    bool insert_row(dataset &set,ah_json_slice value,const char *id,bool primary,bool enterprise,ah_json_slice member_array) {

        row *item=!primary&&set.capacity?set.buckets[hash(id)&(set.capacity-1)]:nullptr;
        while(item&&(item->primary||!ah_eq(item->id,id)))item=item->bucket_next;
        if(item) {
            if(item->enterprise&&!members(*item,member_array))return fail();
            return true;
        }
        else {
            if(!grow(set))return fail();
            item=arena.make<row>();
            if(!item)return fail();
            item->id=arena.copy(id);if(!item->id)return fail();
            size_t slot=hash(id)&(set.capacity-1);
            item->bucket_next=set.buckets[slot];
            set.buckets[slot]=item;
            if(set.tail)set.tail->next=item;
            else set.head=item;
            set.tail=item;
            ++set.count;
        }
        char *body=copy_body(value);if(!body)return fail();
        item->body=body;
        item->length=value.size();
        item->primary=primary;
        item->enterprise=enterprise;
        if(enterprise&&!primary) {
            item->members_start=static_cast<size_t>(member_array.begin-value.begin);
            item->members_end=static_cast<size_t>(member_array.end-value.begin);
            if(!members(*item,member_array))return fail();
        }
        return !arena.failed;
    }
    bool insert(dataset &set,ah_json_slice value) {
        ah_json_slice id_slice,properties;
        if(!ah_combined_json::member(value,"ObjectIdentifier",id_slice)||!ah_combined_json::member(value,"Properties",properties))return fail();
        ah_arena temporary(maximum,4096);const char *id=text(id_slice,&temporary);
        if(!id||!*id)return fail();
        ah_json_slice dn,member_array;
        const bool primary=ah_combined_json::member(properties,"distinguishedname",dn)&&dn.size()>2;
        const bool enterprise=ah_eq(set.name,"groups")&&ah_len(id)>8&&ah_eq(id+ah_len(id)-8,"-S-1-5-9");
        if(enterprise&&!ah_combined_json::member(value,"Members",member_array))return fail();
        return insert_row(set,value,id,primary,enterprise,member_array);
    }
    file *new_file() {
        file *item=ah_alloc<file>(sizeof(file));
        if(!item) {
            fail();
            return nullptr;
        }
        new(item)file(maximum);
        if(files_tail)files_tail->next=item;
        else files=item;
        files_tail=item;
        return item;
    }
    class buffer_writer final {
        ah_buffer &output;
    public:
        explicit buffer_writer(ah_buffer &buffer):output(buffer){}
        bool write(const char *text,size_t length){ah_append(&output,text,length);return !output.failed;}
    };
    class zip_writer final {
        ah_zip &zip;
        bool pretty,quoted=false,escaped=false,pending_open=false;
        unsigned int depth=0;
        char previous=0;
        ah_buffer output;
        bool flush(){if(output.failed)return false;if(output.length&&!zip.write(output.data,output.length))return false;output.length=0;return true;}
        bool put(char value){if(output.length==output.limit&&!flush())return false;ah_append(&output,&value,1);return !output.failed;}
        bool indentation(){if(!put('\n'))return false;for(unsigned int i=0;i<depth;++i)if(!put(' ')||!put(' '))return false;return true;}
    public:
        explicit zip_writer(ah_zip &archive):zip(archive),pretty(ah_pretty_print),output(8192,4096){}
        bool write(const char *text,size_t length){
            if(!pretty)return zip.write(text,length);
            for(size_t i=0;i<length;++i){
                char c=text[i];
                if(quoted){
                    if(!put(c))return false;
                    if(escaped)escaped=false;else if(c=='\\')escaped=true;else if(c=='"'){quoted=false;previous='"';}
                    continue;
                }
                if(static_cast<unsigned char>(c)<=32)continue;
                if(pending_open){if(c!='}'&&c!=']'&&!indentation())return false;pending_open=false;}
                if(c=='"'){quoted=true;if(!put(c))return false;previous=c;continue;}
                if(c=='{'||c=='['){if(++depth>256||!put(c))return false;pending_open=true;previous=c;continue;}
                if(c=='}'||c==']'){if(!depth)return false;--depth;if(previous!='{'&&previous!='['&&!indentation())return false;if(!put(c))return false;previous=c;continue;}
                if(c==','){if(!put(c)||!indentation())return false;previous=c;continue;}
                if(c==':'){if(!put(c)||!put(' '))return false;previous=c;continue;}
                if(!put(c))return false;
                previous=c;
            }
            return true;
        }
        bool complete(){return !depth&&!quoted&&!escaped&&!pending_open&&flush();}
    };
    template<typename Writer>bool emit_dataset(dataset &set,Writer &writer) {
        if(!writer.write("{\"data\":[",9))return fail();
        bool first=true;
        for(row *entry=set.head;entry;entry=entry->next){
            if(!first&&!writer.write(",",1))return fail();
            first=false;
            if(!entry->body)return fail();
            if(entry->enterprise&&!entry->primary){
                if(!writer.write(entry->body,entry->members_start)||!writer.write("[",1))return fail();
                bool member_first=true;
                for(member *item=entry->members;item;item=item->next){if(!member_first&&!writer.write(",",1))return fail();member_first=false;if(!item->body||!writer.write(item->body,item->length))return fail();}
                if(!writer.write("]",1)||!writer.write(entry->body+entry->members_end,entry->length-entry->members_end))return fail();
            }else if(!writer.write(entry->body,entry->length))return fail();

            release_body(*entry);
        }
        if(set.count>static_cast<size_t>(INT64_MAX))return fail();
        ah_buffer metadata(4096,1024);AH_TEXT(&metadata,"],\"meta\":{");
        ah_fields fields(metadata);fields.text("type",set.name);fields.number("count",static_cast<int64_t>(set.count));fields.number("version",6);fields.number("methods",methods);fields.text("collectorversion","AdaptiHound-BOF");AH_TEXT(&metadata,"}}");
        return !metadata.failed&&writer.write(metadata.data,metadata.length);
    }
    public: ah_combined_output(size_t limit,int selected):arena(limit),support_directory(limit),maximum(limit),methods(selected) {
        const char *names[]= {
            "users","computers","groups","domains","ous","gpos","containers","rootcas","aiacas","enterprisecas","ntauthstores","certtemplates","issuancepolicies","sites","siteservers","sitesubnets"
        };
        for(unsigned int i=0; i<16; ++i)data[i].name=names[i];
        if(!ah_output_timestamp(timestamp))invalid=true;
    }
    ~ah_combined_output() {
        for(auto &set:data){for(row *item=set.head;item;item=item->next)release_body(*item);ah_free(set.buckets);}
        while(files) {
            file *next=files->next;
            files->~file();
            ah_free(files);
            files=next;
        }
    }
    const char *primary_domain()const{return targets?targets->name:nullptr;}
    bool discover_domain(const char *name,const char *sid) {
        if(!name||!*name||!sid||!*sid)return true;
        for(domain_target *old=targets; old; old=old->next)if(ah_eq(old->sid,sid))return true;
        domain_target *item=arena.make<domain_target>();
        if(!item)return fail();
        item->name=ah_upper(arena,name);
        item->sid=arena.copy(sid);
        if(!item->name||!item->sid)return fail();
        if(targets_tail)targets_tail->next=item;
        else targets=item;
        targets_tail=item;
        return valid();
    }
    bool discover_trusts(const ah_directory &directory) {
        for(ah_object *trust=directory.objects; trust; trust=trust->next) {
            if(!ah_weq(trust->type,L"trusts"))continue;
            ah_value *value=trust->values("securityIdentifier");
            int64_t direction=0,attributes=0;
            if(!value||!ah_try_property_long(trust,"trustDirection",direction)||!ah_try_property_long(trust,"trustAttributes",attributes))continue;
            const char *sid=ah_sid(arena,reinterpret_cast<unsigned char*>(value->data),value->size);
            if(sid&&!discover_domain(trust->text("cn"),sid))return fail();
        }
        return valid();
    }
    template<typename Consumer>bool discovered_domains(Consumer consume)const {
        for(domain_target *item=targets; item; item=item->next)if(!consume(item->name,item->sid))return false;
        return valid();
    }
    bool valid()const {
        return !invalid&&!arena.failed&&!support_directory.arena.failed;
    }
    void invalidate() {
        invalid=true;
    }
    bool remember_support(const ah_directory &source,const char *context_dn) {
        char *context_key=ah_upper(arena,context_dn);
        if(!context_key)return fail();
        for(ah_object *object=source.objects; object; object=object->next) {
            if(!ah_weq(object->type,L"directoryservices")&&!ah_weq(object->type,L"crossrefs"))continue;
            ah_object *copy=support_directory.add(object->type,object->dn);
            if(!copy)return fail();
            copy->auxiliary_only=true;
            if(!support_directory.value(support_directory.attribute(copy,"__adaptihoundConfigurationContext"),context_key,ah_len(context_key)))return fail();
            for(ah_attr *attribute=object->attributes; attribute; attribute=attribute->next) for(ah_value *value=attribute->values; value; value=value->next) if(!support_directory.value(support_directory.attribute(copy,attribute->name),value->data,value->size))return fail();
        }
        return valid();
    }
    bool restore_support(ah_directory &destination,const char *context_dn) {
        char *context_key=ah_upper(arena,context_dn);
        if(!context_key)return fail();
        for(ah_object *object=support_directory.objects; object; object=object->next) {
            if(!ah_eq(object->text("__adaptihoundConfigurationContext"),context_key))continue;
            ah_object *copy=destination.add(object->type,object->dn);
            if(!copy)return fail();
            copy->auxiliary_only=true;
            for(ah_attr *attribute=object->attributes; attribute; attribute=attribute->next) {
                if(ah_eq(attribute->name,"__adaptihoundConfigurationContext"))continue;
                for(ah_value *value=attribute->values; value; value=value->next) if(!destination.value(destination.attribute(copy,attribute->name),value->data,value->size))return fail();
            }
        }
        return valid()&&!destination.arena.failed;
    }
    bool configuration_once(const char *dn) {
        char *normalized=ah_upper(arena,dn);
        if(!normalized) {
            fail();
            return false;
        }
        for(context *old=contexts; old; old=old->next)if(ah_eq(old->dn,normalized))return false;
        context *item=arena.make<context>();
        if(!item) {
            fail();
            return false;
        }
        item->dn=normalized;
        item->next=contexts;
        contexts=item;
        return true;
    }
    bool capture(const char *name,const ah_buffer &json) {
        if(finalized||!valid()||json.failed||!json.data||!json.length)return fail();
        dataset *set=nullptr;
        for(auto &candidate:data)if(ah_eq(candidate.name,name))set=&candidate;
        if(!set)return fail();
        ah_json_slice source {
            json.data,json.data+json.length
        },array,meta,type,count_slice,version_slice,methods_slice;
        if(!ah_combined_json::member(source,"data",array)||!ah_combined_json::member(source,"meta",meta)||!ah_combined_json::member(meta,"type",type)||!ah_combined_json::member(meta,"count",count_slice)||!ah_combined_json::member(meta,"version",version_slice)||!ah_combined_json::member(meta,"methods",methods_slice))return fail();
        char *type_name=text(type);
        int64_t count=0,version=0,mask=0;
        if(!type_name||!ah_eq(type_name,name)||!number(count_slice,count)||count<0||!number(version_slice,version)||version!=6||!number(methods_slice,mask)||mask!=methods)return fail();
        size_t seen=0;
        if(!ah_combined_json::array(array,[&](ah_json_slice value) {
            ++seen; return insert(*set,value);
        })||seen!=static_cast<uint64_t>(count))return fail();
        return valid();
    }
    bool capture_row(const char *name,const char *id,bool primary,bool enterprise,const ah_buffer &json) {
        if(finalized||!valid()||!id||!*id||json.failed||!json.data||!json.length)return fail();
        dataset *set=nullptr;for(auto &candidate:data)if(ah_eq(candidate.name,name))set=&candidate;
        if(!set)return fail();
        const size_t id_length=ah_len(id);
        const bool expected_enterprise=ah_eq(name,"groups")&&id_length>8&&ah_eq(id+id_length-8,"-S-1-5-9");
        if(enterprise!=expected_enterprise)return fail();
        ah_json_slice source{json.data,json.data+json.length},identifier,properties,dn,member_array;
        if(!valid_utf8(source))return fail();
        if(!ah_combined_json::member(source,"ObjectIdentifier",identifier)||!ah_combined_json::member(source,"Properties",properties)||properties.size()<2||*properties.begin!='{')return fail();
        ah_arena temporary(maximum,4096);const char *actual=text(identifier,&temporary);
        if(!actual||!ah_eq(actual,id))return fail();
        bool has_dn=ah_combined_json::member(properties,"distinguishedname",dn);
        if(has_dn&&(dn.size()<2||*dn.begin!='"'||dn.end[-1]!='"'))return fail();
        if(primary!=(has_dn&&dn.size()>2))return fail();
        if(enterprise&&!ah_combined_json::member(source,"Members",member_array))return fail();
        if(!insert_row(*set,source,id,primary,enterprise,member_array))return fail();
        return valid();
    }
    bool capture_calls(const ah_directory &directory) {
        if(finalized||!valid())return false;
        for(auto *source=directory.call_status; source; source=source->next) {
            ah_call_status *item=arena.make<ah_call_status>();
            if(!item)return fail();
            item->computer=source->computer?arena.copy(source->computer):nullptr;
            item->task=source->task?arena.copy(source->task):nullptr;
            item->status=source->status?arena.copy(source->status):nullptr;
            item->object_id=source->object_id?arena.copy(source->object_id):nullptr;
            if(arena.failed)return fail();
            if(calls_tail)calls_tail->next=item;
            else calls=item;
            calls_tail=item;
        }
        return valid();
    }
    bool finish(const char *output,const ah_profile *profile,const char *domain) {
        if(finalized||!valid())return false;
        finalized=true;
        size_t json_count=0;
        ah_zip zip(maximum,ah_zip_password);
        for(auto &set:data) {
            if(!set.count)continue;
            file *item=new_file();
            if(!item)return false;
            item->name=ah_output_name(arena,set.name,"json",timestamp);
            if(!item->name)return fail();
            if(ah_no_zip){
                buffer_writer writer(item->body);
                if(!emit_dataset(set,writer)||(ah_pretty_print&&!ah_pretty_json(item->body)))return fail();
            }else{
                if(!zip.begin(item->name))return fail();
                zip_writer writer(zip);
                if(!emit_dataset(set,writer)||!writer.complete()||!zip.end())return fail();
            }
            ++json_count;
        }
        if(ah_track_computer_calls&&calls) {
            file *item=new_file();
            if(!item)return false;
            item->csv=true;
            item->name=ah_output_name(arena,"compstatus","csv",timestamp);
            AH_TEXT(&item->body,"ComputerName,Task,Status,ObjectID\r\n");
            for(auto *call=calls; call; call=call->next) {
                ah_csv_cell(item->body,call->computer);
                AH_TEXT(&item->body,", ");
                ah_csv_cell(item->body,call->task);
                AH_TEXT(&item->body,", ");
                ah_csv_cell(item->body,call->status);
                AH_TEXT(&item->body,", ");
                ah_csv_cell(item->body,call->object_id);
                AH_TEXT(&item->body,"\r\n");
            }
            if(!item->name||item->body.failed)return fail();
        }
        char *archive=nullptr;
        if(!ah_no_zip&&(json_count||methods==0)) {
            const char *base=output&&*output?output:ah_default_filename(arena,profile,domain);
            archive=base?ah_output_name(arena,base,"zip",timestamp):nullptr;
            if(!archive)return fail();
            if(!zip.finish(methods==0))return fail();
        }

        if(!valid())return false;
        for(file *item=files; item; item=item->next)if(item->body.length>0x7fffffffU)return fail();
        if(archive&&!zip.download(archive,methods==0))return fail();
        for(file *item=files; item; item=item->next)if(item->csv||ah_no_zip)AxDownloadMemory(item->name,item->body.data,static_cast<int>(item->body.length));
        for(size_t i=0;i<16;++i)if(data[i].count||i<4)ah_report_dataset_count(data[i].name,data[i].count);
        return true;
    }
    ah_combined_output(const ah_combined_output&)=delete;
    ah_combined_output &operator=(const ah_combined_output&)=delete;
};
static ah_combined_output *ah_active_combined_output=nullptr;
struct ah_combined_scope final {
    ah_combined_output *previous;
    explicit ah_combined_scope(ah_combined_output &output):previous(ah_active_combined_output) {
        ah_active_combined_output=&output;
    }
    ~ah_combined_scope() {
        ah_active_combined_output=previous;
    }
};
