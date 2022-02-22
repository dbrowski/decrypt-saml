import React, { useState } from "react";
import Avatar from "@mui/material/Avatar";
import Button from "@mui/material/Button";
import Container from "@mui/material/Container";
import TextField from "@mui/material/TextField";
import Box from "@mui/material/Box";
import Grid from "@mui/material/Grid";
import Popover from "@mui/material/Popover";
import Typography from "@mui/material/Typography";
import CssBaseline from "@mui/material/CssBaseline";
import LockOpenIcon from "@mui/icons-material/LockOpen";
import { makestyles } from "@mui/styles";
import { ThemeProvider, createTheme } from "@mui/material/styles";
import SyntaxHighlighter from "react-syntax-highlighter";
import { docco } from "react-syntax-highlighter/dist/esm/styles/hljs";
import { parseString } from "xml2js";
import aesjs from "aes-js";
import CryptoJS from "crypto-js";
import forge from "node-forge";
import format from "xml-formatter";

// const usesxs = makesxs((theme) => ({
//   root: {
//     display: "flex",
//     flexDirection: "column",
//     alignItems: "stretch",
//     justifyContent: "flex-start",
//     color: "#2E4355",
//   },
//   innerMain: {
//     display: "flex",
//     margin: "0",
//     flexDirection: "column",
//     alignItems: "center",
//     justifyContent: "flex-start",
//     color: "#2E4355",
//   },
//   image: {
//     backgroundImage:
//       "url(https://pingidentity.com/content/dam/ping-6-2-assets/open-graph-images/2019/P14C-Build-OG.png)",
//     backgroundRepeat: "no-repeat",
//     backgroundColor: "#576877",
//     backgroundSize: "cover",
//     backgroundPosition: "center",
//     maxHeight: "20%",
//   },
//   avatar: {
//     backgroundColor: "#2E4355",
//   },
//   form: {
//     width: "100%", // Fix IE 11 issue.
//     marginTop: "0",
//   },
//   submit: {
//     backgroundColor: "#2E4355",
//   },
//   typography: {
//     color: "#2E4355",
//     fontSize: "1%",
//   },
//   errorMessage: {
//     color: "red",
//   },
//   infoPaperContainer: {
//     maxHeight: "100%",
//     overflow: "auto",
//   },
//   info: {
//     height: "100%",
//     maxHeight: "100%",
//     color: "#2E4355",
//     margin: "0",
//     padding: "0",
//   },
// }));

const theme = createTheme({
  palette: {
    primary: {
      main: "#2E4355",
    },
    secondary: {
      main: "#576877",
    },
  },
  spacing: 5,
  components: {
    MuiGrid: {
      styleOverrides: {
        root: {
          paddingTop: "2vh",
        },
      },
    },
    // MuiTypography: {
    //   styleOverrides: {
    //     root: {
    //       paddingBottom: 0,
    //     },
    //   },
    // },
  },
});

export default function App() {
  // State variables and setters.
  const [saml, setSaml] = useState("");
  const [privateKey, setPrivateKey] = useState("");
  const [decryptedSaml, setDecryptedSaml] = useState("");
  const [anchorEl, setAnchorEl] = React.useState(null);
  const [samlError, setSamlError] = React.useState(null);

  const open = Boolean(anchorEl);
  const id = open ? "popover" : undefined;

  const handleSubmit = (event) => {
    event.preventDefault();

    try {
      decrypt();
    } catch (e) {
      // Gets the reason for failure.
      let msg = JSON.stringify(e);
      console.error(e);
      console.error(msg);
      setSamlError(msg);
      setAnchorEl(event.currentTarget);
    }
  };

  const handleSAMLChange = (event) => {
    event.preventDefault();
    setSaml(event.target.value);
  };

  const handlePrivateKeyChange = (event) => {
    event.preventDefault();
    setPrivateKey(event.target.value);
  };

  const handleClose = () => {
    setAnchorEl(null);
  };

  const readAsXML = (stringXML) => {
    parseString(stringXML, function (err, result) {
      const samlpResponse = result["samlp:Response"];
      const samlEncryptedAssertion = samlpResponse["saml:EncryptedAssertion"];
      const encryptedData = samlEncryptedAssertion[0]["xenc:EncryptedData"];

      // read encrypted data node from saml request
      const cipherData = encryptedData[0]["xenc:CipherData"];
      const cipherValue = cipherData[0]["xenc:CipherValue"][0];
      const encryptionMethod =
        encryptedData[0]["xenc:EncryptionMethod"][0]["$"];
      const encryptionAlgorithm = encryptionMethod.Algorithm;
      const base64DecodedCipherValue = forge.util.decode64(cipherValue);

      // read key info from saml request
      const keyInfo = encryptedData[0]["ds:KeyInfo"];
      const encryptedKey = keyInfo[0]["xenc:EncryptedKey"];
      const keyCipherData = encryptedKey[0]["xenc:CipherData"];
      const keyCipherValue = keyCipherData[0]["xenc:CipherValue"][0];
      const base64DecodedKeyCipherValue = forge.util.decode64(keyCipherValue);
      const keyEncryptionMethod = encryptedKey[0]["xenc:EncryptionMethod"];
      const keyEncryptionAlgorithm = keyEncryptionMethod[0]["$"]["Algorithm"];

      // Create forge private key from input
      const forgePrivateKey = forge.pki.privateKeyFromPem(privateKey);

      // Use private key to decrypt the encrypted key in the saml request
      const decryptedKey = forgePrivateKey.decrypt(
        base64DecodedKeyCipherValue,
        "RSA-OAEP"
      );

      // Create a decipher using AES-CBC algorithm
      const decipher = forge.cipher.createDecipher("AES-CBC", decryptedKey);
      // Convert the encrypted data to a buffer
      const base64DecodedCipherValueBuffer = forge.util.createBuffer(
        base64DecodedCipherValue
      );
      // Convert encrypted data buffer to bytes
      const base64DecodedCipherValueBytes =
        base64DecodedCipherValueBuffer.getBytes();

      // For aes128-cbc, the iv is the first 16 bytes
      // For aes192-cbc, the iv is the first 24 bytes
      // For aes256-cbc, the iv is the first 32 bytes
      let numOfBytesInIV = -1;
      if (encryptionAlgorithm.endsWith("aes128-cbc")) {
        numOfBytesInIV = 16;
      } else if (encryptionAlgorithm.endsWith("aes192-cbc")) {
        numOfBytesInIV = 24;
      } else if (encryptionAlgorithm.endsWith("aes256-cbc")) {
        numOfBytesInIV = 32;
      }

      if (numOfBytesInIV < 0) {
        throw new Error(
          "Didn't detect an aes-cbc encryption algorithm. Instead got: " +
            encryptionAlgorithm
        );
      }
      // For the data, ignore the iv
      const withoutIV = base64DecodedCipherValueBytes.slice(numOfBytesInIV);
      // Parse the iv (first 16 bytes of encrypted data)
      const iv = base64DecodedCipherValueBytes.slice(0, numOfBytesInIV);
      // create a forge buffer of the data minus the iv
      const withoutIVBuffer = forge.util.createBuffer(withoutIV);

      // start with iv, initialization vector
      decipher.start({ iv: iv });
      // decrypt the rest of the data
      decipher.update(withoutIVBuffer);
      // finish
      const res = decipher.finish(); // check 'result' for true/false
      // get decrypted bytes and convert to utf8
      const decrypted = forge.util.encodeUtf8(decipher.output.getBytes());
      // set the decrypted value text output
      setDecryptedSaml(decrypted);

      console.log("encryptionAlgorithm");
      console.log(encryptionAlgorithm);
      console.log("keyEncryptionAlgorithm");
      console.log(keyEncryptionAlgorithm);

      // console.log(util.inspect(result, false, null));
      return result;
    });
  };

  const decrypt = () => {
    readAsXML(saml);
  };

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <Container>
        <Grid container display="flex" component="main" direction="column">
          <Grid
            container
            item
            xs={12}
            justifyContent="center"
            alignItems="center"
          >
            <Avatar sx={{ bgcolor: "#2E4355" }}>
              <LockOpenIcon />
            </Avatar>
          </Grid>

          <Grid
            item
            container
            direction="column"
            justify="space-between"
            alignItems="stretch"
            xs={12}
            sx={{ flex: "10 1 auto" }}
          >
            <form noValidate onSubmit={handleSubmit}>
              <Grid item xs={12} sx={{ flex: "10 1 auto" }}>
                <Typography component="h5" variant="h5" align="left">
                  SAML Request{" "}
                  <Typography variant="body1" sx={{ display: "inline-flex" }}>
                    (in xml format)
                  </Typography>
                </Typography>
                {/* JWT input field */}
                <TextField
                  variant="outlined"
                  margin="none"
                  required
                  fullWidth
                  id="saml"
                  label="SAML"
                  name="SAML"
                  value={saml}
                  autoFocus
                  multiline
                  maxRows={4}
                  sx={{
                    fontFamily: "Monospace",
                    fontSize: "1vmin",
                  }}
                  onChange={handleSAMLChange}
                />

                {/* Error Message for JWT String Decode */}
                <Popover
                  id={id}
                  open={open}
                  anchorEl={anchorEl}
                  onClose={handleClose}
                  anchorOrigin={{
                    vertical: "center",
                    horizontal: "center",
                  }}
                  transformOrigin={{
                    vertical: "top",
                    horizontal: "center",
                  }}
                >
                  <Typography>{samlError}</Typography>
                </Popover>
              </Grid>

              <Grid item xs={12} sx={{ flex: "10 1 auto" }}>
                <Typography component="h5" variant="h5" align="left">
                  Private Key
                  <Typography variant="body1" sx={{ display: "inline-flex" }}>
                    ("-----BEGIN PRIVATE KEY-----" ... "-----END PRIVATE
                    KEY-----")
                  </Typography>
                </Typography>

                {/* Private key input field */}
                <TextField
                  variant="outlined"
                  margin="none"
                  required
                  fullWidth
                  id="private-key"
                  label="private-key"
                  name="Private-Key"
                  value={privateKey}
                  multiline
                  maxRows={4}
                  sx={{
                    fontFamily: "Monospace",
                    fontSize: "1vmin",
                  }}
                  onChange={handlePrivateKeyChange}
                />
              </Grid>

              <Grid item xs={12} sx={{ flex: "1 0 auto" }}>
                <Button
                  type="submit"
                  fullWidth
                  variant="contained"
                  color="primary"
                >
                  Decrypt
                </Button>
              </Grid>

              <Grid item xs={12} sx={{ flex: "10 0 auto" }}>
                <Typography component="h5" variant="h5" align="left">
                  Decrypted SAML
                </Typography>
                <Box
                  border={1}
                  borderRadius={5}
                  borderColor="#576877"
                  height="100%"
                  width="100%"
                  maxWidth="100%"
                  minHeight="20vh"
                  fontSize="1rem"
                >
                  {decryptedSaml ? (
                    <SyntaxHighlighter
                      language="xml"
                      sx={docco}
                      customstyle={{ marginTop: "0" }}
                    >
                      {format(decryptedSaml)}
                    </SyntaxHighlighter>
                  ) : (
                    ""
                  )}
                </Box>
              </Grid>
            </form>
          </Grid>
        </Grid>
      </Container>
    </ThemeProvider>
  );
}
