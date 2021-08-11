export function toJson(data: any) {
    return JSON.stringify(data, (_, v) => typeof v === 'bigint' ? `${v}n` : v, 4)
        .replace(/"(-?\d+)n"/g, (_, a) => a.toString());
}

export function firstFromMap<T1,T2>(map: Map<T1,T2>, filter: (key: T1, val: T2) => boolean): T2 | undefined {
    for (const elem of map) {
        if (filter(elem[0], elem[1])) {
            return elem[1];
        }
    }

    return undefined;
}