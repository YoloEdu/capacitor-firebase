import Foundation
import Capacitor
import FirebaseAuth
#if RGCFA_INCLUDE_FACEBOOK
import FBSDKLoginKit
#endif
import CryptoKit // Import for nonce generation

class FacebookAuthProviderHandler: NSObject {
    let errorSignInCanceled = "Sign in canceled."
    let errorLinkCanceled = "Link canceled."
    private var pluginImplementation: FirebaseAuthentication
    #if RGCFA_INCLUDE_FACEBOOK
    private var loginManager: LoginManager
    #endif

    init(_ pluginImplementation: FirebaseAuthentication) {
        self.pluginImplementation = pluginImplementation
        #if RGCFA_INCLUDE_FACEBOOK
        loginManager = LoginManager()
        #endif
        super.init()
    }

    func signIn(call: CAPPluginCall) {
        startSignInWithFacebookFlow(call, isLink: false)
    }

    func link(call: CAPPluginCall) {
        startSignInWithFacebookFlow(call, isLink: true)
    }

    func signOut() {
        #if RGCFA_INCLUDE_FACEBOOK
        loginManager.logOut()
        #endif
    }

    private func startSignInWithFacebookFlow(_ call: CAPPluginCall, isLink: Bool) {
        #if RGCFA_INCLUDE_FACEBOOK
        let scopes = call.getArray("scopes", String.self) ?? []
        DispatchQueue.main.async {
            // https://developers.facebook.com/docs/facebook-login/limited-login/faq
            // In response to the upcoming changes to ATT enforcement, we made changes to the iOS SDK and the SDK
            // no longer provides valid user access tokens in scenarios where the user opts out of ATT.
            // The access token validation or Graph API requests may throw errors like OAuthException -
            // “Invalid OAuth access token - Cannot parse access token”. Our recommendation is
            // that users integrate Limited Login following the official documentation:

            // See these for implementation details:
            // https://firebase.google.com/docs/auth/ios/facebook-login#implement_facebook_limited_login
            // https://developers.facebook.com/docs/facebook-login/limited-login/ios

            let nonce = UUID().uuidString
            let viewController = self.pluginImplementation.getPlugin().bridge?.viewController
            let loginConfiguration = LoginConfiguration(
                permissions: ["email", "public_profile"] + scopes,
                tracking: .limited,
                nonce: self.sha256(nonce)
            )

            self.loginManager.logIn(viewController: viewController, configuration: loginConfiguration) { result in
                switch result {
                case .failed(let error):
                    if isLink == true {
                        self.pluginImplementation.handleFailedLink(message: nil, error: error)
                    } else {
                        self.pluginImplementation.handleFailedSignIn(message: nil, error: error)
                    }
                    return
                case .cancelled:
                    if isLink == true {
                        self.pluginImplementation.handleFailedLink(message: self.errorLinkCanceled, error: nil)
                    } else {
                        self.pluginImplementation.handleFailedSignIn(message: self.errorSignInCanceled, error: nil)
                    }
                    return
                case .success:
                    guard let idTokenString = AuthenticationToken.current?.tokenString else {
                        if isLink == true {
                            self.pluginImplementation.handleFailedLink(message: self.errorLinkCanceled, error: nil)
                        } else {
                            self.pluginImplementation.handleFailedSignIn(message: self.errorSignInCanceled, error: nil)
                        }
                        return
                    }

                    let credential = OAuthProvider.credential(withProviderID: "facebook.com",
                                                               idToken: idTokenString,
                                                              rawNonce: nonce)
                    if isLink == true {
                        self.pluginImplementation.handleSuccessfulLink(credential: credential, idToken: idTokenString, nonce: nonce,
                                                                   accessToken: nil, serverAuthCode: nil, displayName: nil, authorizationCode: nil)
                    } else {
                        self.pluginImplementation.handleSuccessfulSignIn(credential: credential, idToken: idTokenString, nonce: nonce,
                                                                     accessToken: nil, displayName: nil, authorizationCode: nil, serverAuthCode: nil)
                    }
                }
            }
        }
        #endif
    }

    @available(iOS 13, *)
    private func sha256(_ input: String) -> String {
      let inputData = Data(input.utf8)
      let hashedData = SHA256.hash(data: inputData)
      let hashString = hashedData.compactMap {
        String(format: "%02x", $0)
      }.joined()

      return hashString
    }

}
