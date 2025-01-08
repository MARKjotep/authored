export declare class Time {
    date: Date;
    constructor(dateMS?: number);
    delta(date2?: number | null, _Date?: boolean): number | Date;
    timed(time?: {
        year?: number;
        month?: number;
        day?: number;
        hour?: number;
        minute?: number;
        second?: number;
    }): Date;
    static delta(date1: number, date2?: number | null): number;
    static get now(): number;
}
