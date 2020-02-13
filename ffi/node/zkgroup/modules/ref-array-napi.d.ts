// Type definitions for ref-array
// Project: https://github.com/TooTallNate/ref-array
// Definitions by: Paul Loyd <https://github.com/loyd>
// Definitions: https://github.com/DefinitelyTyped/DefinitelyTyped

declare module 'ref-array-napi' {
    import { Type } from 'ref-napi';

    export interface ArrayTypeInstance<T> {
        [i: number]: T; length: number; toArray(): T[];
        toJSON(): T[];
        inspect(): string;
        buffer: Buffer;
        slice: (start: number, end?: number) => ArrayTypeInstance<T>;
        ref(): Buffer;
    }

    export interface ArrayType<T> extends Type {
        BYTES_PER_ELEMENT: number;
        fixedLength: number;
        /** The reference to the base type. */
        type: Type;

        /**
         * Accepts a Buffer instance that should be an already-populated with data
         * for the ArrayType. The "length" of the Array is determined by searching
         * through the buffer's contents until an aligned NULL pointer is encountered.
         */
        untilZeros(buffer: Buffer): ArrayTypeInstance<T>;

        new (length?: number): ArrayTypeInstance<T>;
        new (data: number[], length?: number): ArrayTypeInstance<T>;
        new (data: Buffer, length?: number): ArrayTypeInstance<T>;
        (length?: number): ArrayTypeInstance<T>;
        (data: number[], length?: number): ArrayTypeInstance<T>;
        (data: Buffer, length?: number): ArrayTypeInstance<T>;
    }

    /**
     * The array type meta-constructor.
     * The returned constructor's API is highly influenced by the WebGL
     * TypedArray API.
     */
    export var metaConstructor: {
        new <T>(type: Type, length?: number): ArrayType<T>;
        new <T>(type: string, length?: number): ArrayType<T>;
        <T>(type: Type, length?: number): ArrayType<T>;
        <T>(type: string, length?: number): ArrayType<T>;
    };
}
