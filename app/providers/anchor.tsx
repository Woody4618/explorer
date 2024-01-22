import { AnchorProvider, Idl, Program, Wallet } from '@coral-xyz/anchor';
import { NodeWallet } from '@metaplex/js';
import { Connection, Keypair } from '@solana/web3.js';

const cachedAnchorProgramPromises: Record<
    string,
    void | { __type: 'promise'; promise: Promise<void> } | { __type: 'result'; result: Program<Idl> | null }
> = {};

export function useAnchorProgram(programAddress: string, url: string): Program | null {
    const key = `${programAddress}-${url}`;
    const cacheEntry = cachedAnchorProgramPromises[key];

    if (cacheEntry === undefined) {
        const promise = Program.at(
            programAddress,
            new AnchorProvider(new Connection(url), new NodeWallet(Keypair.generate()) as Wallet, {})
        )
            .then(program => {
                cachedAnchorProgramPromises[key] = {
                    __type: 'result',
                    result: program,
                };
            })
            .catch(_ => {
                cachedAnchorProgramPromises[key] = { __type: 'result', result: null };
            });
        cachedAnchorProgramPromises[key] = {
            __type: 'promise',
            promise,
        };
        throw promise;
    } else if (cacheEntry.__type === 'promise') {
        throw cacheEntry.promise;
    }
    return cacheEntry.result;
}

export type AnchorAccount = {
    layout: string;
    account: object;
};
