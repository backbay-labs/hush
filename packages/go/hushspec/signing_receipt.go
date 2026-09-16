package hushspec

import "fmt"

// Receipt signing (RFC 09 P2-06, receipt spec 6).
//
// A receipt on its own is not tamper-evident. Signing it from the outside --
// over its receipt hash, never over a member added to the receipt -- keeps the
// receipt's own hash stable regardless of who signs it or which log it lands
// in.

// SignedReceipt is a receipt together with a signature over its receipt hash.
type SignedReceipt struct {
	Receipt DecisionReceipt `json:"receipt"`
	// Signature is a 0.2 envelope whose `content_hash` is the receipt hash.
	Signature Envelope `json:"signature"`
}

// SignReceipt signs a receipt: the envelope's `content_hash` is the receipt
// hash (receipt spec 6), so the signature covers every field.
//
// `policy_name` and `policy_version` are left unset unless opts provides them;
// a receipt already names its policy.
func SignReceipt(
	receipt *DecisionReceipt,
	privateKeyPEM []byte,
	opts SignOptions,
) (*SignedReceipt, error) {
	if receipt == nil {
		return nil, fmt.Errorf("cannot sign a nil receipt")
	}
	hash, err := receipt.ReceiptHash()
	if err != nil {
		return nil, fmt.Errorf("cannot sign the receipt: %w", err)
	}
	envelope, err := SignContentHash(hash, privateKeyPEM, opts)
	if err != nil {
		return nil, err
	}
	return &SignedReceipt{Receipt: *receipt, Signature: *envelope}, nil
}

// VerifyReceipt verifies a receipt signature: the ten ordered checks of
// signing spec 6.2 with the receipt hash as the content hash.
//
// A receipt that cannot be canonicalized is a [ReasonContentHashMismatch]:
// there is no hash to compare.
func VerifyReceipt(signed *SignedReceipt, opts VerifyOptions) VerifyResult {
	if signed == nil {
		return VerifyResult{
			Reason: ReasonMalformedEnvelope,
			Detail: "no signed receipt was supplied",
		}
	}
	// An unhashable receipt yields "", which check 9 treats as a mismatch.
	hash, _ := signed.Receipt.ReceiptHash()
	return VerifyContentHash(&signed.Signature, hash, opts)
}

// ParseSignedReceipt reads a signed receipt, rejecting unknown fields and any
// receipt version other than the one this SDK implements.
func ParseSignedReceipt(data []byte) (*SignedReceipt, error) {
	var signed SignedReceipt
	if err := strictUnmarshalJSON(data, &signed); err != nil {
		return nil, fmt.Errorf("not a well-formed signed receipt: %w", err)
	}
	if signed.Receipt.ReceiptVersion != ReceiptVersion {
		return nil, fmt.Errorf(
			"unsupported receipt_version %q, expected %q",
			signed.Receipt.ReceiptVersion, ReceiptVersion)
	}
	return &signed, nil
}
