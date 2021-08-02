// @ts-ignore
import lrs from "lrs";

export type LrsSign = {
    sign: string;
}

const sign = (message: string, prvKey: string, pubKeys: string[]) : string => {
    return lrs.sign(message, prvKey, pubKeys);
};