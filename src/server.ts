import { create, toBinary } from '@bufbuild/protobuf';
import { callEngine, ensureEngine } from './wasmLoader';
import { CryptoObjectType } from './proto/discocrypto/v1/common_pb';
import {
    DetectRequestSchema,
    DetectResponseSchema,
    ParseResponseSchema,
    type ParsedObject,
} from './proto/discocrypto/v1/parser_pb';
import { getHandler } from './handlers';

export class CryptoServer {
    async parse(data: Uint8Array, filename: string, options?: Record<string, any>): Promise<Uint8Array> {
        await ensureEngine();

        const detectReq = create(DetectRequestSchema, { data, filename });
        const detectRes = callEngine(
            'detect', detectReq, DetectRequestSchema, DetectResponseSchema,
        );

        if (detectRes.objects.length === 0) {
            throw new Error('Unable to identify any crypto objects in this file');
        }

        const objects: ParsedObject[] = [];

        for (const detected of detectRes.objects) {
            if (detected.type === CryptoObjectType.UNSPECIFIED) {
                continue;
            }
            const handler = getHandler(detected.type);
            objects.push(...handler.parse(data, detected.type, options));
        }

        const response = create(ParseResponseSchema, {
            objects,
            detectedEncoding: detectRes.objects[0].encoding,
        });

        return toBinary(ParseResponseSchema, response);
    }
}
