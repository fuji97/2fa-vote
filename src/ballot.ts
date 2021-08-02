import {Point} from "./types";
import {CeviInput, Proof} from "./proof";
import {LrsSign} from "./lrs";
import {Sign} from "./sign";


export type Ballot = {
    vote: Point;
    proof: Proof<CeviInput>;
    voterSign: LrsSign;
    casterSign: Sign;
};