import React, { useState } from "react";
import Avatar from "@mui/material/Avatar";
import Button from "@mui/material/Button";
import IconButton from "@mui/material/IconButton";
import Container from "@mui/material/Container";
import TextField from "@mui/material/TextField";
import Box from "@mui/material/Box";
import Grid from "@mui/material/Grid";
import Popover from "@mui/material/Popover";
import Typography from "@mui/material/Typography";
import CssBaseline from "@mui/material/CssBaseline";
import Input from "@mui/material/Input";
import LockOpenIcon from "@mui/icons-material/LockOpen";
import PhotoCamera from "@mui/icons-material/PhotoCamera";
import { ThemeProvider, createTheme } from "@mui/material/styles";
import SyntaxHighlighter from "react-syntax-highlighter";
import { githubGist } from "react-syntax-highlighter/dist/esm/styles/hljs";
import { parseString } from "xml2js";
import forge from "node-forge";
import format from "xml-formatter";
import hljs from "highlight.js/lib/core";
import xml from "highlight.js/lib/languages/xml";

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
          paddingTop: "1vh",
        },
      },
    },
    MuiOutlinedInput: {
      styleOverrides: {
        root: {
          fontSize: ".75rem",
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
  const [privateKeyFile, setPrivateKeyFile] = useState("");
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

      return result;
    });
  };

  const decrypt = () => {
    readAsXML(saml);
  };

  const onChange = (event) => {
    const f = event.target.files[0];
    setPrivateKeyFile(f);
    uploadFile(f);
    event.stopPropagation();
    event.preventDefault();
  };

  // On file upload (click the upload button)
  const uploadFile = (pkf) => {
    const pkfFileReader = new FileReader();

    pkfFileReader.readAsText(pkf);
    pkfFileReader.onload = (e) => {
      setPrivateKey(pkfFileReader.result);
    };

    setPrivateKey(pkfFileReader.result);
  };

  hljs.registerLanguage("xml", xml);

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
            <form
              noValidate
              onSubmit={handleSubmit}
              style={{ maxWidth: "100%" }}
            >
              <Grid item xs={12} sx={{ flex: "10 1 auto" }}>
                <Typography component="h5" variant="h5" align="left">
                  SAML Assertion/Request/Response{" "}
                  <Typography variant="caption" sx={{ display: "inline-flex" }}>
                    (in xml format;s i.e., it's been decoded)
                  </Typography>
                </Typography>

                {/* SAML input field */}
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
                  maxRows={6}
                  sx={{
                    fontFamily: "Monospace",
                  }}
                  onChange={handleSAMLChange}
                />

                {/* Error Message for SAML Decrypt */}
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

              <Grid container item xs={12} sx={{ flex: "10 1 auto" }}>
                <Grid item xs={12}>
                  <Typography component="h5" variant="h5" align="left">
                    Encryption Key{" "}
                    <Typography
                      variant="caption"
                      sx={{ display: "inline-flex" }}
                    >
                      (.pem, "-----BEGIN PRIVATE KEY----- ... -----END PRIVATE
                      KEY-----")
                    </Typography>
                  </Typography>
                </Grid>
                <Grid item xs={12}>
                  {/* Private key input field */}
                  {/* <TextField
                  variant="outlined"
                  margin="dense"
                  required
                  fullWidth
                  id="private-key"
                  label="Private Key"
                  name="Private-Key"
                  value={privateKey}
                  multiline
                  maxRows={6}
                  sx={{
                    fontFamily: "Monospace",
                  }}
                  onChange={handlePrivateKeyChange}
                /> */}

                  <label htmlFor="contained-button-file">
                    <Input
                      accept=".pem"
                      id="contained-button-file"
                      type="file"
                      onChange={onChange}
                    />
                  </label>
                </Grid>
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

              <Grid container item xs={12} sx={{ flex: "10 0 auto" }}>
                <Typography component="h5" variant="h5" align="left">
                  Decrypted SAML
                </Typography>
                <Box
                  display="flex"
                  border={1}
                  borderRadius={5}
                  borderColor="#576877"
                  height="100%"
                  width="100%"
                  maxWidth="100%"
                  minHeight="20vh"
                  maxHeight="25vh"
                  fontSize="1rem"
                >
                  {decryptedSaml ? (
                    <SyntaxHighlighter
                      language="xml"
                      style={githubGist}
                      customStyle={{
                        margin: 0,
                        maxWidth: "100%",
                        maxHeight: "100%",
                        overflowY: "auto !important",
                      }}
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
