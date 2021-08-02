import * as bjj from "./babyjubjub"

let p1 = bjj.Base8.mulScalar(15n);
console.log(bjj.Base8.toString());
console.log(p1.toString());