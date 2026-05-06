# **🔐 VeriHash Onboarding: Building Your GitHub Digital Endorsement Library**

Welcome to VeriHash. To allow AI to objectively evaluate your intellectual output, you need to establish a globally accessible, cryptographically secure, and immutable "Evidence Library." We use **GitHub Gist** as the underlying foundation for this library.

### **Why GitHub Gist?**

We chose GitHub Gist as our base for several critical reasons:

* **Anchor of Trust**: GitHub is the world’s most reputable platform for digital identity hosting, making it the primary data source for AI agents to recognize professional identities.  
* **AI-Friendliness**: Gists are natively "machine-readable," allowing AI to read and verify your private-key-signed "intellectual fingerprints" via stable URLs without relying on third-party intermediaries.  
* **Deterministic State**: Version control in Gists ensures data immutability. For AI intermediaries, this "certainty" is the foundation for generating objective rules and moving beyond the "digital jungle."

## **Step 1: Create Your GitHub Account**

GitHub is the world’s largest community for developers and data scientists, and it serves as a highly credible platform for "Digital Identity."

1. **Visit the Website**: Go to [github.com](https://github.com/).  
2. **Sign Up**: Click **Sign up**. We recommend using your professional email address.  
3. **Choose a Username**: Your username will appear in all your credential links (e.g., gist.github.com/yourname). For freelancers and professionals, we suggest using your real name or a consistent brand ID.  
4. **Verify**: Follow the prompts to complete the CAPTCHA and email verification. **Email verification is mandatory** to use the API features.

## **Step 2: Generate Your "Key" (Personal Access Token)**

VeriHash requires your authorization to send encrypted credentials to GitHub on your behalf. This key is called a **PAT (Personal Access Token)**.

1. **Access Settings**: Once logged in, click your profile icon in the top-right corner \-\> **Settings**.  
2. **Developer Settings**: Scroll to the bottom of the left-hand menu and click **Developer settings**.  
3. **Generate Token**:  
   * Select **Tokens (classic)**.  
   * Click **Generate new token** \-\> **Generate new token (classic)**.  
4. **Configure Permissions**:  
   * **Note**: Enter VeriHash\_Access.  
   * **Expiration**: We recommend selecting No expiration to ensure long-term automated synchronization.  
   * **Select Scopes**: **Check only one box: gist**. This grants VeriHash permission to read and write your code snippets/credentials while keeping your private repositories inaccessible and secure.  
5. **Save the Key**: Click **Generate token** at the bottom.  
   * **⚠️ IMPORTANT**: A string starting with ghp\_ will appear. **Copy and save it immediately**. It will only be displayed once.

## **Step 3: Understanding Gists — Your Digital Case Files**

**What is a Gist?**

A Gist is a lightweight storage service provided by GitHub for code snippets, legal drafts, or JSON data.

* **Uniqueness**: Every Gist has a globally unique URL.  
* **Version Control**: Every modification leaves a "History" (Revision) trail. No one can silently alter a credential once it's published.  
* **Human & Machine Friendly**: It can be read by humans via a browser and by AI crawlers as structured data.

**In VeriHash, Gists play two roles:**

1. **Credential Archive (VC Gist)**: Every time you "Mint" a project, a new Gist is created containing the "intellectual fingerprint" of that specific work.  
2. **Public Root Index**: This is a **permanently fixed** Gist that acts as a map, listing all your work records. This is how AI intermediaries discover and index your entire career history.

## **Step 4: Connecting VeriHash to the Cloud**

1. Open the VeriHash application.  
2. Go to the **Settings** page.  
3. In the **GitHub PAT** field, paste your ghp\_ token.  
4. Click **Save**.

## **🛡️ Security & Privacy**

* **Data Sanitization**: VeriHash automatically de-identifies and sanitizes data before uploading. Your local file paths and sensitive document contents **never** leave your computer.  
* **One-Way Signing**: Data uploaded to Gist is signed with your local private key. Even if GitHub's servers were compromised, your signature cannot be forged.  
* **Complete Control**: You have the absolute "Right to be Forgotten." You can manually delete any Gist directly via the GitHub web interface at any time.

**You are now ready to establish your professional presence in the AI era. Go ahead and Mint your first digital badge of expertise\!**