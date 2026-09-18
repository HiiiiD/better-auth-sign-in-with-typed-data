import type { BetterAuthClientPlugin } from "better-auth/client";
import type { siwtd } from "./index";

export const siwtdClient = () => {
	return {
		id: "siwtd",
		$InferServerPlugin: {} as ReturnType<typeof siwtd>,
		pathMethods: {
			"/siwtd/nonce": "POST",
			"/siwtd/verify": "POST",
		},
	} satisfies BetterAuthClientPlugin;
};
