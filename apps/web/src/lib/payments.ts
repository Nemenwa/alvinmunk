/**
 * Classic XLM payment (White-belt Level-1 rubric: "send an XLM transaction on
 * testnet" with success/failure + tx hash feedback). Works with any Wallet provider
 * (Freighter for the Level-1 demo, or passkey/dev).
 */
import { Asset, Operation, TransactionBuilder } from '@stellar/stellar-sdk';
import { server, networkPassphrase } from './stellar';
import type { Wallet } from './wallet';

export interface PaymentResult {
  hash: string;
  status: 'SUCCESS' | 'FAILED' | 'PENDING';
}

/** Send `amount` XLM from the wallet to `to`. Returns hash + final-ish status. */
export async function sendXlm(wallet: Wallet, to: string, amount: string): Promise<PaymentResult> {
  const account = await server.getAccount(wallet.address);
  const tx = new TransactionBuilder(account, { fee: '1000', networkPassphrase })
    .addOperation(Operation.payment({ destination: to, asset: Asset.native(), amount }))
    .setTimeout(60)
    .build();

  const signedXdr = await wallet.sign(tx.toXDR());
  const signed = TransactionBuilder.fromXDR(signedXdr, networkPassphrase);
  const sent = await server.sendTransaction(signed);

  if (sent.status === 'ERROR') {
    throw new Error(`payment rejected: ${JSON.stringify(sent.errorResult)}`);
  }

  // Poll briefly so the UI can show a confirmed success/failure.
  // Transient decode/RPC errors are caught and retried; only on-chain FAILURE throws.
  let lastErr: unknown;
  for (let i = 0; i < 15; i++) {
    try {
      const res = await server.getTransaction(sent.hash);
      if (res.status === 'SUCCESS') return { hash: sent.hash, status: 'SUCCESS' };
      if (res.status === 'FAILED') return { hash: sent.hash, status: 'FAILED' };
    } catch (e) {
      if (e instanceof Error && e.message.endsWith('failed on-chain')) {
        return { hash: sent.hash, status: 'FAILED' };
      }
      lastErr = e; // transient decode/RPC error — keep polling
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  // Budget exhausted: the tx may still land, so return PENDING with an explorer link.
  return { hash: sent.hash, status: 'PENDING' };
}
