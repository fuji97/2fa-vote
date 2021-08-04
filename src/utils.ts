export function toJson(data: any) {
    return JSON.stringify(data, (_, v) => typeof v === 'bigint' ? `${v}n` : v, 4)
        .replace(/"(-?\d+)n"/g, (_, a) => a.toString());
}

