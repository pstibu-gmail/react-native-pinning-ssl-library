import { NativeModules } from "react-native";

const { PinningSslLibrary } = NativeModules;

export async function isSSLValid({ url, hashes, domainNames }) {
  try {
    const isValid = await PinningSslLibrary.getStatus(url, hashes, domainNames);
    return isValid;
  } catch (e) {
    throw new Error(e);
  }
}
