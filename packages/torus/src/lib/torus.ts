import Web3AuthClient from "./web3auth-client";
import type { KeyPair } from "near-api-js";
import { InMemorySigner, keyStores, utils } from "near-api-js";
import type { SafeEventEmitterProvider } from "@web3auth/base";
import { getActiveAccount } from "@near-wallet-selector/core";
import type {
  WalletModuleFactory,
  WalletBehaviourFactory,
  Network,
  Account,
  Web3AuthWallet,
  Optional,
  Transaction,
  FinalExecutionOutcome,
} from "@near-wallet-selector/core";
import { signTransactions } from "@near-wallet-selector/wallet-utils";
import { icon } from "./icon";
import { getED25519Key } from "@toruslabs/openlogin-ed25519";

interface TorusExtraOptions {
  clientId: string;
}

interface TorusState {
  client: Web3AuthClient;
  keyPair: KeyPair | null;
  provider: SafeEventEmitterProvider | null;
  signer: InMemorySigner;
  keyStore: keyStores.InMemoryKeyStore;
}

export interface TorusParams {
  clientId: string;
  iconUrl?: string;
  deprecated?: boolean;
}

const getAccountIdFromPublicKey = (publicKeyData: Uint8Array) => {
  return Buffer.from(publicKeyData).toString("hex");
};

const getKeyPair = async (
  provider: SafeEventEmitterProvider,
  keyStore: keyStores.InMemoryKeyStore,
  network: Network
) => {
  const privateKey = await provider.request<string>({
    method: "private_key",
  });

  if (!privateKey) {
    throw new Error("No private key found");
  }

  const finalPrivKey = getED25519Key(privateKey).sk;

  const keyPair = utils.key_pair.KeyPairEd25519.fromString(
    utils.serialize.base_encode(finalPrivKey)
  );

  const accountId = getAccountIdFromPublicKey(keyPair.getPublicKey().data);

  keyStore.setKey(network.networkId, accountId, keyPair);

  return keyPair;
};

const setupTorusState = async (
  clientId: string,
  network: Network
): Promise<TorusState> => {
  const client = new Web3AuthClient(clientId, network);
  await client.init();

  const keyStore = new keyStores.InMemoryKeyStore();
  const signer = new InMemorySigner(keyStore);

  let keyPair = null;
  const provider = client.getProvider();

  if (provider) {
    keyPair = await getKeyPair(provider, keyStore, network);
  }

  return {
    client,
    provider,
    keyPair,
    signer,
    keyStore,
  };
};

const Torus: WalletBehaviourFactory<
  Web3AuthWallet,
  { params: TorusExtraOptions }
> = async ({ options, params, store, logger, provider }) => {
  const _state = await setupTorusState(params.clientId, options.network);

  const transformTransactions = (
    transactions: Array<Optional<Transaction, "signerId" | "receiverId">>
  ): Array<Transaction> => {
    const { contract } = store.getState();

    if (!contract) {
      throw new Error("Wallet not signed in");
    }

    const account = getActiveAccount(store.getState());

    if (!account) {
      throw new Error("No active account");
    }

    return transactions.map((transaction) => {
      return {
        signerId: transaction.signerId || account.accountId,
        receiverId: transaction.receiverId || contract.contractId,
        actions: transaction.actions,
      };
    });
  };

  function getAccounts(): Array<Account> {
    if (!_state.keyPair) {
      return [];
    }

    const publicKey = _state.keyPair.getPublicKey().data;
    const accountId = getAccountIdFromPublicKey(publicKey);

    return [{ accountId }];
  }

  return {
    signIn: async ({ loginProvider, email }) => {
      _state.provider = await _state.client.connect(loginProvider, email);

      if (!_state.provider) {
        throw new Error("No provider found");
      }

      _state.keyPair = await getKeyPair(
        _state.provider,
        _state.keyStore,
        options.network
      );

      return getAccounts();
    },
    signOut: async () => {
      return _state.client.disconnect();
    },
    getAccounts: async () => {
      return getAccounts();
    },
    verifyOwner: () => {
      throw new Error("Method not supported");
    },
    signAndSendTransaction: async ({ signerId, receiverId, actions }) => {
      logger.log("signAndSendTransaction", { signerId, receiverId, actions });

      const [signedTx] = await signTransactions(
        transformTransactions([{ signerId, receiverId, actions }]),
        _state.signer,
        options.network
      );

      return provider.sendTransaction(signedTx);
    },
    signAndSendTransactions: async ({ transactions }) => {
      logger.log("signAndSendTransactions", { transactions });

      const signedTransactions = await signTransactions(
        transformTransactions(transactions),
        _state.signer,
        options.network
      );

      const results: Array<FinalExecutionOutcome> = [];

      for (let i = 0; i < signedTransactions.length; i++) {
        results.push(await provider.sendTransaction(signedTransactions[i]));
      }

      return results;
    },
  };
};

export function setupTorus({
  clientId,
  iconUrl = icon,
  deprecated = false,
}: TorusParams): WalletModuleFactory<Web3AuthWallet> {
  return async () => {
    return {
      id: "torus",
      type: "web3auth",
      metadata: {
        name: "Torus Wallet",
        description: "Connect to dApps with social logins.",
        iconUrl,
        deprecated,
        available: true,
      },
      init: (options) => {
        return Torus({
          ...options,
          params: {
            clientId,
          },
        });
      },
    };
  };
}