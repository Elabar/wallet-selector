import React, { Fragment, useCallback, useEffect, useState } from "react";
import { providers, utils } from "near-api-js";
import type {
  AccountView,
  CodeResult,
} from "near-api-js/lib/providers/provider";
import type {
  SignedMessage,
  SignMessageParams,
  Transaction,
} from "@near-wallet-selector/core";
import { verifyFullKeyBelongsToUser } from "@near-wallet-selector/core";
import { verifySignature } from "@near-wallet-selector/core";

import type { Account, Message } from "../interfaces";
import { useWalletSelector } from "../contexts/WalletSelectorContext";
import { CONTRACT_ID } from "../constants";
import SignIn from "./SignIn";
import Form from "./Form";
import Messages from "./Messages";

type Submitted = SubmitEvent & {
  target: { elements: { [key: string]: HTMLInputElement } };
};

const SUGGESTED_DONATION = "0";
const BOATLOAD_OF_GAS = utils.format.parseNearAmount("0.00000000003")!;
const GUESTBOOK_CONTRACT_ID = "guest-book.testnet";

interface GetAccountBalanceProps {
  provider: providers.Provider;
  accountId: string;
}

const getAccountBalance = async ({
  provider,
  accountId,
}: GetAccountBalanceProps) => {
  try {
    const { amount } = await provider.query<AccountView>({
      request_type: "view_account",
      finality: "final",
      account_id: accountId,
    });
    const bn = BigInt(amount);
    return { hasBalance: bn !== BigInt(0) };
  } catch {
    return { hasBalance: false };
  }
};

const Content: React.FC = () => {
  const { selector, modal, accounts, accountId } = useWalletSelector();
  const [account, setAccount] = useState<Account | null>(null);
  const [messages, setMessages] = useState<Array<Message>>([]);
  const [loading, setLoading] = useState<boolean>(false);

  const getAccount = useCallback(async (): Promise<Account | null> => {
    if (!accountId) {
      return null;
    }

    const { network } = selector.options;
    const provider = new providers.JsonRpcProvider({ url: network.nodeUrl });

    const { hasBalance } = await getAccountBalance({
      provider,
      accountId,
    });

    if (!hasBalance) {
      window.alert(
        `Account ID: ${accountId} has not been founded. Please send some NEAR into this account.`
      );
      const wallet = await selector.wallet();
      await wallet.signOut();
      return null;
    }

    return provider
      .query<AccountView>({
        request_type: "view_account",
        finality: "final",
        account_id: accountId,
      })
      .then((data) => ({
        ...data,
        account_id: accountId,
      }));
  }, [accountId, selector]);

  const getMessages = useCallback(() => {
    const { network } = selector.options;
    const provider = new providers.JsonRpcProvider({ url: network.nodeUrl });

    return provider
      .query<CodeResult>({
        request_type: "call_function",
        account_id: CONTRACT_ID,
        method_name: "getMessages",
        args_base64: "",
        finality: "optimistic",
      })
      .then((res) => JSON.parse(Buffer.from(res.result).toString()));
  }, [selector]);

  useEffect(() => {
    // TODO: don't just fetch once; subscribe!
    getMessages().then(setMessages);

    const timeoutId = setTimeout(() => {
      verifyMessageBrowserWallet();
    }, 500);

    return () => {
      clearTimeout(timeoutId);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!accountId) {
      return setAccount(null);
    }

    setLoading(true);

    getAccount().then((nextAccount) => {
      setAccount(nextAccount);
      setLoading(false);
    });
  }, [accountId, getAccount]);

  const handleSignIn = () => {
    modal.show();
  };

  const handleSignOut = async () => {
    const wallet = await selector.wallet();

    wallet.signOut().catch((err) => {
      console.log("Failed to sign out");
      console.error(err);
    });
  };

  const handleSwitchWallet = () => {
    modal.show();
  };

  const handleSwitchAccount = () => {
    const currentIndex = accounts.findIndex((x) => x.accountId === accountId);
    const nextIndex = currentIndex < accounts.length - 1 ? currentIndex + 1 : 0;

    const nextAccountId = accounts[nextIndex].accountId;

    selector.setActiveAccount(nextAccountId);

    alert("Switched account to " + nextAccountId);
  };

  const addMessages = useCallback(
    async (message: string, donation: string, multiple: boolean) => {
      const { contract } = selector.store.getState();
      const wallet = await selector.wallet();
      if (!multiple) {
        return wallet
          .signAndSendTransaction({
            signerId: accountId!,
            actions: [
              {
                type: "FunctionCall",
                params: {
                  methodName: "addMessage",
                  args: { text: message },
                  gas: BOATLOAD_OF_GAS,
                  deposit: utils.format.parseNearAmount(donation)!,
                },
              },
            ],
          })
          .catch((err) => {
            alert("Failed to add message " + err);
            console.log("Failed to add message");

            throw err;
          });
      }

      const transactions: Array<Transaction> = [];

      for (let i = 0; i < 2; i += 1) {
        transactions.push({
          signerId: accountId!,
          receiverId: contract!.contractId,
          actions: [
            {
              type: "FunctionCall",
              params: {
                methodName: "addMessage",
                args: {
                  text: `${message} (${i + 1}/2)`,
                },
                gas: BOATLOAD_OF_GAS,
                deposit: utils.format.parseNearAmount(donation)!,
              },
            },
          ],
        });
      }

      return wallet.signAndSendTransactions({ transactions }).catch((err) => {
        alert("Failed to add messages exception " + err);
        console.log("Failed to add messages");

        throw err;
      });
    },
    [selector, accountId]
  );

  const handleVerifyOwner = async () => {
    const wallet = await selector.wallet();
    try {
      const owner = await wallet.verifyOwner({
        message: "test message for verification",
      });

      if (owner) {
        alert(`Signature for verification: ${JSON.stringify(owner)}`);
      }
    } catch (err) {
      const message =
        err instanceof Error ? err.message : "Something went wrong";
      alert(message);
    }
  };

  const verifyMessage = async (
    message: SignMessageParams,
    signedMessage: SignedMessage
  ) => {
    const verifiedSignature = verifySignature({
      message: message.message,
      nonce: message.nonce,
      recipient: message.recipient,
      publicKey: signedMessage.publicKey,
      signature: signedMessage.signature,
      callbackUrl: message.callbackUrl,
    });
    const verifiedFullKeyBelongsToUser = await verifyFullKeyBelongsToUser({
      publicKey: signedMessage.publicKey,
      accountId: signedMessage.accountId,
      network: selector.options.network,
    });

    const isMessageVerified = verifiedFullKeyBelongsToUser && verifiedSignature;

    const alertMessage = isMessageVerified
      ? "Successfully verified"
      : "Failed to verify";

    alert(
      `${alertMessage} signed message: '${
        message.message
      }': \n ${JSON.stringify(signedMessage)}`
    );
  };

  const verifyMessageBrowserWallet = useCallback(async () => {
    const urlParams = new URLSearchParams(
      window.location.hash.substring(1) // skip the first char (#)
    );
    const accId = urlParams.get("accountId") as string;
    const publicKey = urlParams.get("publicKey") as string;
    const signature = urlParams.get("signature") as string;

    if (!accId && !publicKey && !signature) {
      return;
    }

    const message: SignMessageParams = JSON.parse(
      localStorage.getItem("message")!
    );

    const signedMessage = {
      accountId: accId,
      publicKey,
      signature,
    };

    await verifyMessage(message, signedMessage);

    const url = new URL(location.href);
    url.hash = "";
    url.search = "";
    window.history.replaceState({}, document.title, url);
    localStorage.removeItem("message");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleSubmit = useCallback(
    async (e: Submitted) => {
      e.preventDefault();

      const { fieldset, message, donation, multiple } = e.target.elements;

      fieldset.disabled = true;

      return addMessages(message.value, donation.value || "0", multiple.checked)
        .then(() => {
          return getMessages()
            .then((nextMessages) => {
              setMessages(nextMessages);
              message.value = "";
              donation.value = SUGGESTED_DONATION;
              fieldset.disabled = false;
              multiple.checked = false;
              message.focus();
            })
            .catch((err) => {
              alert("Failed to refresh messages");
              console.log("Failed to refresh messages");

              throw err;
            });
        })
        .catch((err) => {
          console.error(err);

          fieldset.disabled = false;
        });
    },
    [addMessages, getMessages]
  );

  const handleSignMessage = async () => {
    const wallet = await selector.wallet();

    const message = "test message to sign";
    const nonce = Buffer.from(crypto.getRandomValues(new Uint8Array(32)));

    if (wallet.type === "browser") {
      localStorage.setItem(
        "message",
        JSON.stringify({
          message,
          nonce: [...nonce],
          recipient: GUESTBOOK_CONTRACT_ID,
          callbackUrl: location.href,
        })
      );
    }

    try {
      const signedMessage = await wallet.signMessage({
        message,
        nonce,
        recipient: GUESTBOOK_CONTRACT_ID,
      });
      if (signedMessage) {
        await verifyMessage(
          { message, nonce, recipient: GUESTBOOK_CONTRACT_ID },
          signedMessage
        );
      }
    } catch (err) {
      const errMsg =
        err instanceof Error ? err.message : "Something went wrong";
      alert(errMsg);
    }
  };

  const handleSendMultipleTransactions = async () => {
    const wallet = await selector.wallet();

    await wallet.signAndSendTransactions({
      transactions: [
        {
          // Deploy your own version of https://github.com/near-examples/rust-counter using Gitpod to get a valid receiverId.
          signerId: accountId!,
          receiverId: "dev-1648806797290-14624341764914",
          actions: [
            {
              type: "FunctionCall",
              params: {
                methodName: "increment",
                args: {},
                gas: BOATLOAD_OF_GAS,
                deposit: utils.format.parseNearAmount("0")!,
              },
            },
          ],
        },
        {
          signerId: accountId!,
          receiverId: GUESTBOOK_CONTRACT_ID,
          actions: [
            {
              type: "FunctionCall",
              params: {
                methodName: "addMessage",
                args: { text: "Hello World!" },
                gas: BOATLOAD_OF_GAS,
                deposit: utils.format.parseNearAmount("0")!,
              },
            },
          ],
        },
      ],
    });
  };

  const handleSendMultipleTransactionsWithoutSignerId = async () => {
    const { contract } = selector.store.getState();
    const wallet = await selector.wallet();

    await wallet.signAndSendTransactions({
      transactions: [
        {
          // Deploy your own version of https://github.com/near-examples/rust-counter using Gitpod to get a valid receiverId.
          // signerId: accountId!,
          receiverId: "dev-1648806797290-14624341764914",
          actions: [
            {
              type: "FunctionCall",
              params: {
                methodName: "increment",
                args: {},
                gas: BOATLOAD_OF_GAS,
                deposit: utils.format.parseNearAmount("0")!,
              },
            },
          ],
        },
        {
          // signerId: accountId!,
          receiverId: contract!.contractId,
          actions: [
            {
              type: "FunctionCall",
              params: {
                methodName: "addMessage",
                args: { text: "Hello World!" },
                gas: BOATLOAD_OF_GAS,
                deposit: utils.format.parseNearAmount("0")!,
              },
            },
          ],
        },
      ],
    });
  };

  const handleSendMultiNearTransactions = async () => {
    const wallet = await selector.wallet();

    await wallet.signAndSendTransactions({
      transactions: [
        {
          // Deploy your own version of https://github.com/near-examples/rust-counter using Gitpod to get a valid receiverId.
          signerId: accountId!,
          receiverId: "ft1.enleapstack.testnet",
          actions: [
            {
              type: "FunctionCall",
              params: {
                methodName: "something",
                args: {
                  receiver_id: "compound",
                  amount: "1000000000000000000000",
                  msg: "invest",
                },
                gas: BOATLOAD_OF_GAS,
                deposit: utils.format.parseNearAmount("0.1")!,
              },
            },
            {
              type: "FunctionCall",
              params: {
                methodName: "someOtherThing",
                args: {
                  receiver_id: "compound",
                  amount: "1000000000000000000000",
                  msg: "invest",
                },
                gas: BOATLOAD_OF_GAS,
                deposit: utils.format.parseNearAmount("1.1")!,
              },
            },
          ],
        },
      ],
    });
  };

  const handleSendFtTransactions = async () => {
    const wallet = await selector.wallet();

    await wallet.signAndSendTransactions({
      transactions: [
        {
          // Deploy your own version of https://github.com/near-examples/rust-counter using Gitpod to get a valid receiverId.
          signerId: accountId!,
          receiverId: "ft1.enleapstack.testnet",
          actions: [
            {
              type: "FunctionCall",
              params: {
                methodName: "ft_transfer",
                args: {
                  receiver_id: "compound",
                  amount: "1000000000000000000000",
                  msg: "invest",
                },
                gas: BOATLOAD_OF_GAS,
                deposit: utils.format.parseNearAmount("0")!,
              },
            },
          ],
        },
      ],
    });
  };

  const handleSendFtWithNearTransactions = async () => {
    const wallet = await selector.wallet();

    await wallet.signAndSendTransactions({
      transactions: [
        {
          // Deploy your own version of https://github.com/near-examples/rust-counter using Gitpod to get a valid receiverId.
          signerId: accountId!,
          receiverId: "usdn.testnet",
          actions: [
            {
              type: "FunctionCall",
              params: {
                methodName: "ft_transfer",
                args: {
                  receiver_id: "compound",
                  amount: "2000000000000000000000",
                  msg: "invest",
                },
                gas: BOATLOAD_OF_GAS,
                deposit: utils.format.parseNearAmount("10")!,
              },
            },
          ],
        },
      ],
    });
  };

  const handleSendMultiFtTransactions = async () => {
    const wallet = await selector.wallet();

    await wallet.signAndSendTransactions({
      transactions: [
        {
          // Deploy your own version of https://github.com/near-examples/rust-counter using Gitpod to get a valid receiverId.
          signerId: accountId!,
          receiverId: "ft1.enleapstack.testnet",
          actions: [
            {
              type: "FunctionCall",
              params: {
                methodName: "ft_transfer",
                args: {
                  receiver_id: "compound",
                  amount: "1000000000000000000000",
                  msg: "invest",
                },
                gas: BOATLOAD_OF_GAS,
                deposit: utils.format.parseNearAmount("0")!,
              },
            },
          ],
        },
        {
          // Deploy your own version of https://github.com/near-examples/rust-counter using Gitpod to get a valid receiverId.
          signerId: accountId!,
          receiverId: "usdn.testnet",
          actions: [
            {
              type: "FunctionCall",
              params: {
                methodName: "ft_transfer",
                args: {
                  receiver_id: "compound",
                  amount: "2000000000000000000000",
                  msg: "invest",
                },
                gas: BOATLOAD_OF_GAS,
                deposit: utils.format.parseNearAmount("10")!,
              },
            },
          ],
        },
      ],
    });
  };

  const handleSendManyManyFtTransactions = async () => {
    const wallet = await selector.wallet();

    await wallet.signAndSendTransactions({
      transactions: [
        {
          // Deploy your own version of https://github.com/near-examples/rust-counter using Gitpod to get a valid receiverId.
          signerId: accountId!,
          receiverId: "ft1.enleapstack.testnet",
          actions: [
            {
              type: "FunctionCall",
              params: {
                methodName: "ft_transfer",
                args: {
                  receiver_id: "compound",
                  amount: "1000000000000000000000",
                  msg: "invest",
                },
                gas: BOATLOAD_OF_GAS,
                deposit: utils.format.parseNearAmount("0")!,
              },
            },
          ],
        },
        {
          // Deploy your own version of https://github.com/near-examples/rust-counter using Gitpod to get a valid receiverId.
          signerId: accountId!,
          receiverId: "usdn.testnet",
          actions: [
            {
              type: "FunctionCall",
              params: {
                methodName: "ft_transfer",
                args: {
                  receiver_id: "compound",
                  amount: "2000000000000000000000",
                  msg: "invest",
                },
                gas: BOATLOAD_OF_GAS,
                deposit: utils.format.parseNearAmount("10")!,
              },
            },
            {
              type: "FunctionCall",
              params: {
                methodName: "ft_transfer",
                args: {
                  receiver_id: "compound",
                  amount: "2000000000000000000000",
                  msg: "invest",
                },
                gas: BOATLOAD_OF_GAS,
                deposit: utils.format.parseNearAmount("10")!,
              },
            },
          ],
        },
        {
          // Deploy your own version of https://github.com/near-examples/rust-counter using Gitpod to get a valid receiverId.
          signerId: accountId!,
          receiverId: "usdn.testnet",
          actions: [
            {
              type: "FunctionCall",
              params: {
                methodName: "ft_transfer",
                args: {
                  receiver_id: "compound",
                  amount: "2000000000000000000000",
                  msg: "invest",
                },
                gas: BOATLOAD_OF_GAS,
                deposit: utils.format.parseNearAmount("10")!,
              },
            },
          ],
        },
        {
          // Deploy your own version of https://github.com/near-examples/rust-counter using Gitpod to get a valid receiverId.
          signerId: accountId!,
          receiverId: "tinkerunion_nft.testenleap.testnet",
          actions: [
            {
              type: "FunctionCall",
              params: {
                methodName: "ft_transfer",
                args: {
                  receiver_id: "compound",
                  amount: "2000000000000000000000",
                  msg: "invest",
                },
                gas: BOATLOAD_OF_GAS,
                deposit: utils.format.parseNearAmount("10")!,
              },
            },
          ],
        },
        {
          // Deploy your own version of https://github.com/near-examples/rust-counter using Gitpod to get a valid receiverId.
          signerId: accountId!,
          receiverId: "x.testcandy.testnet",
          actions: [
            {
              type: "FunctionCall",
              params: {
                methodName: "ft_transfer",
                args: {
                  receiver_id: "compound",
                  amount: "2000000000000000000000",
                  msg: "invest",
                },
                gas: BOATLOAD_OF_GAS,
                deposit: utils.format.parseNearAmount("10")!,
              },
            },
          ],
        },
      ],
    });
  };

  const handleSendNftTransactions = async () => {
    const wallet = await selector.wallet();

    await wallet.signAndSendTransactions({
      transactions: [
        {
          // Deploy your own version of https://github.com/near-examples/rust-counter using Gitpod to get a valid receiverId.
          signerId: accountId!,
          receiverId: "nft1.enleapstack.testnet",
          actions: [
            {
              type: "FunctionCall",
              params: {
                methodName: "nft_transfer",
                args: {
                  receiver_id: "compound",
                  token_id: "1005",
                  msg: "invest",
                },
                gas: BOATLOAD_OF_GAS,
                deposit: utils.format.parseNearAmount("0")!,
              },
            },
          ],
        },
      ],
    });
  };

  const handleSendNftWithNearTransactions = async () => {
    const wallet = await selector.wallet();

    await wallet.signAndSendTransactions({
      transactions: [
        {
          // Deploy your own version of https://github.com/near-examples/rust-counter using Gitpod to get a valid receiverId.
          signerId: accountId!,
          receiverId: "nft1.enleapstack.testnet",
          actions: [
            {
              type: "FunctionCall",
              params: {
                methodName: "nft_transfer",
                args: {
                  receiver_id: "compound",
                  token_id: "1005",
                  msg: "invest",
                },
                gas: BOATLOAD_OF_GAS,
                deposit: utils.format.parseNearAmount("10")!,
              },
            },
          ],
        },
      ],
    });
  };

  const handleSendFtAndNftTransactions = async () => {
    const wallet = await selector.wallet();

    await wallet.signAndSendTransactions({
      transactions: [
        {
          // Deploy your own version of https://github.com/near-examples/rust-counter using Gitpod to get a valid receiverId.
          signerId: accountId!,
          receiverId: "ft1.enleapstack.testnet",
          actions: [
            {
              type: "FunctionCall",
              params: {
                methodName: "ft_transfer",
                args: {
                  receiver_id: "compound",
                  amount: "1000000000000000000000",
                  msg: "invest",
                },
                gas: BOATLOAD_OF_GAS,
                deposit: utils.format.parseNearAmount("10")!,
              },
            },
          ],
        },
        {
          // Deploy your own version of https://github.com/near-examples/rust-counter using Gitpod to get a valid receiverId.
          signerId: accountId!,
          receiverId: "usdn.testnet",
          actions: [
            {
              type: "FunctionCall",
              params: {
                methodName: "ft_transfer",
                args: {
                  receiver_id: "compound",
                  amount: "2000000000000000000000",
                  msg: "invest",
                },
                gas: BOATLOAD_OF_GAS,
                deposit: utils.format.parseNearAmount("10")!,
              },
            },
            {
              type: "FunctionCall",
              params: {
                methodName: "ft_transfer",
                args: {
                  receiver_id: "compound",
                  amount: "2000000000000000000000",
                  msg: "invest",
                },
                gas: BOATLOAD_OF_GAS,
                deposit: utils.format.parseNearAmount("10")!,
              },
            },
          ],
        },
        {
          // Deploy your own version of https://github.com/near-examples/rust-counter using Gitpod to get a valid receiverId.
          signerId: accountId!,
          receiverId: "nft1.enleapstack.testnet",
          actions: [
            {
              type: "FunctionCall",
              params: {
                methodName: "nft_transfer",
                args: {
                  receiver_id: "compound",
                  token_id: "1005",
                  msg: "invest",
                },
                gas: BOATLOAD_OF_GAS,
                deposit: utils.format.parseNearAmount("10")!,
              },
            },
          ],
        },
      ],
    });
  };

  const handleTransferSomeFundsToGuestbook = async () => {
    const wallet = await selector.wallet();
    await wallet.signAndSendTransaction({
      signerId: accountId!,
      receiverId: "pebbletest.testnet",
      actions: [
        {
          type: "Transfer",
          params: {
            deposit: utils.format.parseNearAmount("1.25") || "0",
          },
        },
      ],
    });
  };

  const handleAddFullAccessKey = async () => {
    const wallet = await selector.wallet();

    await wallet.signAndSendTransactions({
      transactions: [
        {
          signerId: accountId!,
          receiverId: accountId!,
          actions: [
            {
              type: "AddKey",
              params: {
                publicKey:
                  "ed25519:6yjPa9QiwQC6RPwM1ho5BHXbyLkTJvADpgcWf9hjaPoj",
                accessKey: {
                  permission: "FullAccess",
                },
              },
            },
          ],
        },
      ],
    });
  };

  const handleRemoveFullAccessKey = async () => {
    const wallet = await selector.wallet();

    await wallet.signAndSendTransactions({
      transactions: [
        {
          signerId: accountId!,
          receiverId: accountId!,
          actions: [
            {
              type: "DeleteKey",
              params: {
                publicKey:
                  "ed25519:47DukAY98H5ow7Bic3iwFtaMDAnyEt3MV4U6wToVCkco",
              },
            },
          ],
        },
      ],
    });
  };

  const handleContractDeploy = async () => {
    const wallet = await selector.wallet();

    await wallet.signAndSendTransactions({
      transactions: [
        {
          signerId: accountId!,
          receiverId: accountId!,
          actions: [
            {
              type: "DeployContract",
              params: {
                code: Buffer.from("asdasdasdasd()"),
              },
            },
          ],
        },
      ],
    });
  };

  const handleDeleteAccount = async () => {
    const wallet = await selector.wallet();

    await wallet.signAndSendTransactions({
      transactions: [
        {
          signerId: accountId!,
          receiverId: accountId!,
          actions: [
            {
              type: "DeleteAccount",
              params: {
                beneficiaryId: "pebbledev.testnet",
              },
            },
          ],
        },
      ],
    });
  };

  const handleSendWithYoctoNearTransactions = async () => {
    const wallet = await selector.wallet();

    await wallet.signAndSendTransactions({
      transactions: [
        {
          // Deploy your own version of https://github.com/near-examples/rust-counter using Gitpod to get a valid receiverId.
          signerId: accountId!,
          receiverId: "ft1.enleapstack.testnet",
          actions: [
            {
              type: "FunctionCall",
              params: {
                methodName: "something",
                args: {
                  receiver_id: "compound",
                  amount: "1000000000000000000000",
                  msg: "invest",
                },
                gas: BOATLOAD_OF_GAS,
                deposit: "1",
              },
            },
          ],
        },
      ],
    });
  };

  const handleSendManyFtAndNftTransactions = async () => {
    const wallet = await selector.wallet();

    await wallet.signAndSendTransactions({
      transactions: [
        {
          // Deploy your own version of https://github.com/near-examples/rust-counter using Gitpod to get a valid receiverId.
          signerId: accountId!,
          receiverId: "ft1.enleapstack.testnet",
          actions: [
            {
              type: "FunctionCall",
              params: {
                methodName: "ft_transfer",
                args: {
                  receiver_id: "compound",
                  amount: "1000000000000000000000",
                  msg: "invest",
                },
                gas: BOATLOAD_OF_GAS,
                deposit: utils.format.parseNearAmount("0")!,
              },
            },
          ],
        },
        {
          // Deploy your own version of https://github.com/near-examples/rust-counter using Gitpod to get a valid receiverId.
          signerId: accountId!,
          receiverId: "usdn.testnet",
          actions: [
            {
              type: "FunctionCall",
              params: {
                methodName: "ft_transfer",
                args: {
                  receiver_id: "compound",
                  amount: "2000000000000000000000",
                  msg: "invest",
                },
                gas: BOATLOAD_OF_GAS,
                deposit: utils.format.parseNearAmount("10")!,
              },
            },
            {
              type: "FunctionCall",
              params: {
                methodName: "ft_transfer",
                args: {
                  receiver_id: "compound",
                  amount: "2000000000000000000000",
                  msg: "invest",
                },
                gas: BOATLOAD_OF_GAS,
                deposit: utils.format.parseNearAmount("10")!,
              },
            },
          ],
        },
        {
          // Deploy your own version of https://github.com/near-examples/rust-counter using Gitpod to get a valid receiverId.
          signerId: accountId!,
          receiverId: "usdn.testnet",
          actions: [
            {
              type: "FunctionCall",
              params: {
                methodName: "ft_transfer",
                args: {
                  receiver_id: "compound",
                  amount: "2000000000000000000000",
                  msg: "invest",
                },
                gas: BOATLOAD_OF_GAS,
                deposit: utils.format.parseNearAmount("10")!,
              },
            },
          ],
        },
        {
          // Deploy your own version of https://github.com/near-examples/rust-counter using Gitpod to get a valid receiverId.
          signerId: accountId!,
          receiverId: "tinkerunion_nft.testenleap.testnet",
          actions: [
            {
              type: "FunctionCall",
              params: {
                methodName: "ft_transfer",
                args: {
                  receiver_id: "compound",
                  amount: "2000000000000000000000",
                  msg: "invest",
                },
                gas: BOATLOAD_OF_GAS,
                deposit: utils.format.parseNearAmount("10")!,
              },
            },
          ],
        },
        {
          // Deploy your own version of https://github.com/near-examples/rust-counter using Gitpod to get a valid receiverId.
          signerId: accountId!,
          receiverId: "x.testcandy.testnet",
          actions: [
            {
              type: "FunctionCall",
              params: {
                methodName: "ft_transfer",
                args: {
                  receiver_id: "compound",
                  amount: "2000000000000000000000",
                  msg: "invest",
                },
                gas: BOATLOAD_OF_GAS,
                deposit: utils.format.parseNearAmount("10")!,
              },
            },
          ],
        },
        {
          // Deploy your own version of https://github.com/near-examples/rust-counter using Gitpod to get a valid receiverId.
          signerId: accountId!,
          receiverId: "nft1.enleapstack.testnet",
          actions: [
            {
              type: "FunctionCall",
              params: {
                methodName: "nft_transfer",
                args: {
                  receiver_id: "compound",
                  token_id: "1005",
                  msg: "invest",
                },
                gas: BOATLOAD_OF_GAS,
                deposit: utils.format.parseNearAmount("10")!,
              },
            },
          ],
        },
      ],
    });
  };

  if (loading) {
    return null;
  }

  if (!account) {
    return (
      <Fragment>
        <div>
          <button onClick={handleSignIn}>Log in</button>
        </div>
        <div style={{ marginTop: 30 }}>
          {/* @ts-ignore */}
          <w3m-button label="Log in with Ethereum" />
        </div>
        <SignIn />
      </Fragment>
    );
  }

  return (
    <Fragment>
      <div>
        <button onClick={handleSignOut}>Log out</button>
        <button onClick={handleSwitchWallet}>Switch Wallet</button>
        <button onClick={handleVerifyOwner}>Verify Owner</button>
        <button onClick={handleSignMessage}>Sign Message</button>
        {accounts.length > 1 && (
          <button onClick={handleSwitchAccount}>Switch Account</button>
        )}
      </div>
      {selector.store.getState().selectedWalletId === "ethereum-wallets" && (
        <div style={{ marginTop: 30 }}>
          {/* @ts-ignore */}
          <w3m-button label="Log in with Ethereum" />
        </div>
      )}
      <br />
      <div>
        <button onClick={handleSendMultipleTransactions}>
          Send Multiple Transactions
        </button>
        <button onClick={handleSendMultipleTransactionsWithoutSignerId}>
          Send Multiple Transactions (No Signer)
        </button>
      </div>
      <br />
      <div>
        <button onClick={handleTransferSomeFundsToGuestbook}>
          Transfer some funds
        </button>
      </div>
      <br />
      <div>
        <button onClick={handleAddFullAccessKey}>
          Add a full access key (bad)
        </button>
        <button onClick={handleRemoveFullAccessKey}>
          Remove a full access key (bad)
        </button>
        <button onClick={handleContractDeploy}>
          Deploy contract to account (bad)
        </button>
        <button onClick={handleDeleteAccount}>Delete account (bad)</button>
      </div>
      <br />
      <div>
        <button onClick={handleSendWithYoctoNearTransactions}>
          Send With yocto Near Transactions
        </button>
        <button onClick={handleSendMultiNearTransactions}>
          Send Multiple Near Transactions
        </button>
        <button onClick={handleSendFtTransactions}>Send FT Transactions</button>
        <button onClick={handleSendFtWithNearTransactions}>
          Send FT With Near Transactions
        </button>
        <button onClick={handleSendMultiFtTransactions}>
          Send Multiple FT Transactions
        </button>
        <button onClick={handleSendManyManyFtTransactions}>
          Send Many Many FT Transactions
        </button>
      </div>
      <br />
      <div>
        <button onClick={handleSendNftTransactions}>
          Send Single NFT Transactions
        </button>
        <button onClick={handleSendNftWithNearTransactions}>
          Send NFT With Near Transactions
        </button>
        <button onClick={handleSendFtAndNftTransactions}>
          Send FT & NFT Transactions
        </button>
        <button onClick={handleSendManyFtAndNftTransactions}>
          Send Many NFT & NFT Transactions
        </button>
      </div>
      <Form
        account={account}
        onSubmit={(e) => handleSubmit(e as unknown as Submitted)}
      />
      <Messages messages={messages} />
    </Fragment>
  );
};

export default Content;
