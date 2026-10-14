"""Lossless storage of synthesized event words; logical PCs never change."""
MAGIC=b'KVM\x03'

# Insert only when saved blob bytes pay for this reader even at one literal
# character per byte. Actual string/Unicode encodings usually save more.
READER='''    function r.scode(n)
        local mode=r.u8()
        if mode==0 then return r.iword end
        if mode~=1 then error("bad synthesis storage") end
        local dictionary={}
        local size=r.uint()
        if size==0 or size>n then error("bad synthesis dictionary") end
        for j=1,size do
            local fields=r.u32()
            if fields>=67108864 then error("bad synthesis operands") end
            dictionary[j]=fields
        end
        local blocks,last={},0
        local count=r.uint()
        if count==0 or count>math.floor(n/3) then error("bad synthesis count") end
        for j=1,count do
            local delta,width=r.uint(),r.uint()
            local start=last+delta
            last=start+width-1
            if delta==0 or width<3 or last>n then error("bad synthesis span") end
            blocks[j]={start,last}
        end
        local slot=1
        return function(i)
            local block=blocks[slot]
            if not block or i<block[1] then return r.iword() end
            local fields=dictionary[r.uint()]
            local a,b,c=r.u8(),r.u8(),r.u8()
            if not fields or not c or c>=64 then error("bad synthesis word") end
            local entropy=a+b*256+c*65536
            local word=__SYN_WORD__
            if i==block[2] then slot=slot+1 end
            return word
        end
    end
'''


def _uint(value):
    result=bytearray()
    while value>=128:result.append((value&127)|128);value>>=7
    result.append(value)
    return bytes(result)


def padding(layout):
    used=set(range(7))
    for name,width in (('A',8),('B',9),('C',9),('V',8)):
        used.update(range(layout[name],layout[name]+width))
    return [bit for bit in range(48) if bit not in used]


def reader_source(layout):
    terms=['entropy%128',f'math.floor(entropy/128)%256*{1<<layout["V"]}',
        f'fields%256*{1<<layout["A"]}',f'math.floor(fields/256)%512*{1<<layout["B"]}',
        f'math.floor(fields/131072)*{1<<layout["C"]}']
    terms.extend(f'math.floor(entropy/{1<<(15+j)})%2*{1<<bit}' for j,bit in enumerate(padding(layout)))
    return READER.replace('__SYN_WORD__','+'.join(terms))


def reader_overhead(layout):
    return (len(reader_source(layout).encode())+len('; local _stored_code=r.scode(n)')
        +len('local raw64=_stored_code(i)')-len('local raw64=r.iword()'))


def components(word,layout):
    fields=((word>>layout['A'])&255)|(((word>>layout['B'])&511)<<8)|(((word>>layout['C'])&511)<<17)
    entropy=(word&127)|(((word>>layout['V'])&255)<<7)
    entropy|=sum(((word>>bit)&1)<<(15+j) for j,bit in enumerate(padding(layout)))
    return fields,entropy


def restore(fields,entropy,layout):
    return ((entropy&127)|(((entropy>>7)&255)<<layout['V'])|((fields&255)<<layout['A'])
        |(((fields>>8)&511)<<layout['B'])|((fields>>17)<<layout['C'])
        |sum(((entropy>>(15+j))&1)<<bit for j,bit in enumerate(padding(layout))))


def _pack(words,regions,layout):
    merged=[]
    for start,width in sorted(regions):
        if (type(start) is not int or type(width) is not int or start<0 or width<3 or
            (start+width)*6>len(words) or merged and start<merged[-1][0]+merged[-1][1]):
            raise ValueError('invalid synthesis storage span')
        if merged and merged[-1][0]+merged[-1][1]==start:
            merged[-1]=(merged[-1][0],merged[-1][1]+width)
        else:merged.append((start,width))
    dictionary={};selected=[];previous_end=0
    for start,width in merged:
        payload=bytearray()
        for offset in range(start*6,(start+width)*6,6):
            fields,entropy=components(int.from_bytes(words[offset:offset+6],'little'),layout)
            index=dictionary.setdefault(fields,len(dictionary)+1)
            payload.extend(_uint(index));payload.extend(entropy.to_bytes(3,'little'))
        descriptor=_uint(start+1-previous_end)+_uint(width)
        selected.append((start,width,payload,descriptor));previous_end=start+width
    if not selected:return b'\0'+words,0
    directory=b''.join(row[3] for row in selected)
    payload=bytearray();cursor=0
    for start,width,data,_ in selected:
        payload.extend(words[cursor*6:start*6]);payload.extend(data);cursor=start+width
    payload.extend(words[cursor*6:])
    entries=b''.join(fields.to_bytes(4,'little') for fields in dictionary)
    packed=b'\1'+_uint(len(dictionary))+entries+_uint(len(selected))+directory+payload
    if len(packed)>=1+len(words):return b'\0'+words,0
    return bytes(packed),len(selected)


def pack_sections(blob,sections,layout):
    """Rewrite once after legacy serialization, preserving its RNG order."""
    changes=[];blocks=0;raw=stored=0
    for start,end,regions in sections:
        words=blob[start:end];packed,count=_pack(words,regions,layout)
        changes.append((start,end,packed));blocks+=count;raw+=len(words);stored+=len(packed)
    savings=raw-stored
    reader_bytes=len(reader_source(layout).encode())
    minimum_savings=reader_overhead(layout)
    if not blocks or savings<=minimum_savings:
        return blob,{'synthesis_storage_saved_bytes':0,'synthesis_storage_candidate_savings':max(0,savings),
            'synthesis_storage_reader_bytes':reader_bytes,'synthesis_storage_minimum_savings':minimum_savings,'synthesis_storage_blocks':0}
    result=bytearray(MAGIC);cursor=4
    for start,end,packed in changes:
        result.extend(blob[cursor:start]);result.extend(packed);cursor=end
    result.extend(blob[cursor:])
    return bytes(result),{'synthesis_storage_saved_bytes':savings,'synthesis_storage_raw_bytes':raw,
        'synthesis_storage_stored_bytes':stored,'synthesis_storage_reader_bytes':reader_bytes,
        'synthesis_storage_minimum_savings':minimum_savings,
        'synthesis_storage_blocks':blocks,'synthesis_storage_prototypes':len(sections)}


def read_words(reader,count,*,collect=True,layout=None):
    """Python validation/integrity patching counterpart of r.scode."""
    mode=reader.u8()
    if mode not in (0,1):raise ValueError('bad synthesis storage')
    blocks=[];last=0;dictionary=[]
    if mode:
        size=reader.uint()
        if not 0<size<=count:raise ValueError('bad synthesis dictionary')
        for _ in range(size):
            fields=int.from_bytes(bytes(reader.u8() for _ in range(4)),'little')
            if fields>=1<<26:raise ValueError('bad synthesis operands')
            dictionary.append(fields)
        size=reader.uint()
        if not 0<size<=count//3:raise ValueError('bad synthesis count')
        for _ in range(size):
            delta,width=reader.uint(),reader.uint();start=last+delta;last=start+width-1
            if delta==0 or width<3 or last>count:raise ValueError('bad synthesis span')
            blocks.append((start,last))
    if layout is None:
        from ..backends.handler_codec import DEFAULT_INSTR_LAYOUT
        layout=DEFAULT_INSTR_LAYOUT
    result=bytearray();slot=0
    for index in range(1,count+1):
        block=blocks[slot] if slot<len(blocks) else None
        if block is None or index<block[0]:
            data=reader._data[reader._pos:reader._pos+6];reader.skip(6)
        else:
            operand=reader.uint()
            entropy=int.from_bytes(bytes(reader.u8() for _ in range(3)),'little')
            if not 1<=operand<=len(dictionary) or entropy>=1<<22:raise ValueError('bad synthesis word')
            data=restore(dictionary[operand-1],entropy,layout).to_bytes(6,'little') if collect else b''
            if index==block[1]:slot+=1
        if collect:result.extend(data)
    return bytes(result)


def prepare_reader(source,blob,layout):
    if blob[:4]!=MAGIC:return source
    header='or r.u8()~=2 then'
    marker='    function r.header()'
    proto='local n=r.uint(); p.code={}'
    word='local raw64=r.iword()'
    if any(source.count(x)!=1 for x in (header,marker,proto,word)):
        raise ValueError('synthesis storage reader boundaries missing')
    return source.replace(header,'or r.u8()~=3 then').replace(marker,reader_source(layout)+marker).replace(
        proto,proto+'; local _stored_code=r.scode(n)').replace(word,'local raw64=_stored_code(i)')
