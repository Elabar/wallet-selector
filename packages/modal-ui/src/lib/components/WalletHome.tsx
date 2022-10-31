import React, { useEffect, useState } from "react";
import { WhatWallet } from "./WhatWallet";
import Icon from "../images/black-white.jpg";
import type {
  InjectedWallet,
  ModuleState,
  WalletSelector,
} from "@near-wallet-selector/core";
import { ModalHeader } from "./ModalHeader";
import { BackArrow } from "./BackArrow";
import PlusCircleIcon from "../images/plus-circle.svg";
import { translate } from "@near-wallet-selector/core";

interface WalletHomeProps {
  selector: WalletSelector;
  onCloseModal: () => void;
  onSignInToCreateWallet: () => void;
}

type WalletHomeRoutes = "WalletInfo" | "GetWallets";

export const WalletHome: React.FC<WalletHomeProps> = ({
  selector,
  onCloseModal,
  onSignInToCreateWallet,
}) => {
  const [topThreeModules, setTopThreeModules] = useState<Array<ModuleState>>(
    []
  );
  const [route, setRoute] = useState<WalletHomeRoutes>("WalletInfo");

  useEffect(() => {
    const subscription = selector.store.observable.subscribe((state) => {
      const filterByType = (item: { type: string }) => {
        return item.type !== "bridge" && item.type !== "hardware";
      };

      const filteredModules = state.modules.filter(filterByType);

      setTopThreeModules(filteredModules.slice(0, 3));
    });
    return () => subscription.unsubscribe();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const goToWallet = (module: ModuleState) => {
    const { networkId } = selector.options.network;
    let url = "";

    if (module.type === "injected") {
      url = (module as ModuleState<InjectedWallet>).metadata.downloadUrl;
    }

    // TODO: improve links to wallets other than injected type.
    if (module.id === "my-near-wallet") {
      const subdomain = networkId === "testnet" ? "testnet" : "app";
      url = `https://${subdomain}.mynearwallet.com`;
    }

    if (module.id === "opto-wallet") {
      const subdomain = networkId === "testnet" ? "app.testnet" : "app";
      url = `https://${subdomain}.optowallet.com`;
    }

    if (module.id === "near-wallet") {
      const subdomain = networkId === "testnet" ? "testnet." : "";
      url = `https://wallet.${subdomain}near.org`;
    }

    if (module.id === "here-wallet") {
      url = "https://herewallet.app/";
    }

    if (
      (url === "" && module.type === "bridge") ||
      module.type === "hardware"
    ) {
      return;
    }

    window.open(url, "_blank");
  };

  return (
    <div className="wallet-home-wrapper">
      <div className="nws-modal-header-wrapper">
        {route === "GetWallets" && (
          <BackArrow
            onClick={() => {
              setRoute("WalletInfo");
            }}
          />
        )}
        <ModalHeader
          title={
            route === "GetWallets"
              ? translate("modal.wallet.getAWallet")
              : translate("modal.wallet.whatIsAWallet")
          }
          onCloseModal={onCloseModal}
        />
      </div>
      {route === "GetWallets" && (
        <div className="get-wallet-wrapper">
          {topThreeModules.map((module) => {
            const { iconUrl, name, description } = module.metadata;
            return (
              <div className="single-wallet-get" key={module.id}>
                <div className="icon">
                  <img src={iconUrl} alt={name} />
                </div>
                <div className="content">
                  <div className="title">{name}</div>
                  <div className="description">{description}</div>
                </div>
                <div className="button-get">
                  <button
                    className="get-wallet"
                    onClick={() => {
                      goToWallet(module);
                    }}
                  >
                    Get
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}
      {route === "WalletInfo" && (
        <>
          <div className="wallet-info-wrapper what-wallet-hide">
            <WhatWallet
              title={translate("modal.wallet.secureAndManage")}
              description={translate("modal.wallet.safelyStore")}
              icon={Icon}
            />
            <WhatWallet
              title={translate("modal.wallet.logInToAny")}
              description={translate("modal.wallet.noNeedToCreate")}
              icon={Icon}
            />
            <div className="button-spacing" />
            <button
              className="middleButton"
              onClick={() => {
                setRoute("GetWallets");
              }}
            >
              {translate("modal.wallet.getAWallet")}
            </button>
            <div
              className="web3auth-info-action"
              onClick={onSignInToCreateWallet}
            >
              <span>{translate("modal.wallet.loginWithSocial")}</span>
              <img src={PlusCircleIcon} alt="plus in circle" />
            </div>
          </div>
          <div className="what-wallet-mobile">
            <p>{translate("modal.wallet.useAWallet")}</p>
            <button
              className="middleButton"
              onClick={() => {
                setRoute("GetWallets");
              }}
            >
              {translate("modal.wallet.getAWallet")}
            </button>
            <div
              className="web3auth-info-action"
              onClick={onSignInToCreateWallet}
            >
              <span>{translate("modal.wallet.loginWithSocial")}</span>
              <img src={PlusCircleIcon} alt="plus in circle" />
            </div>
          </div>
        </>
      )}
    </div>
  );
};
