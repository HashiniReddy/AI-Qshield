# AI-QShield — Day 2 QR Forensics Experiment

## Objective
Evaluate QR decoding and image-forensics measurements under clean, blurred, and cropped image conditions.

## Test Results

| Image | Dimensions | Decoding | Margin Difference | Finder Analysis |
|---|---|---|---|---|
| Clean | 330 × 330 | Success | 1.00 | Available |
| Blurred | 330 × 330 | Success | 0.38 | Available |
| Cropped | 264 × 264 | Failed | Unavailable | Unavailable |

## Observations
1. The clean and blurred images both decoded to `https://example.com`.
2. Blurring changed the measured dark-pixel density in the approximate finder regions.
3. The cropped image was not decoded by OpenCV in this experiment.
4. Geometry and finder-region analysis were unavailable when corner points were not detected.

## Limitations
- The experiment uses one original QR image and two transformed versions.
- Finder-region density is a heuristic, not a definitive finder-pattern or tampering detector.
- Margin consistency does not certify QR-standard compliance.
- A failed decode does not establish that an image is malicious.

## Conclusion
The experiment demonstrates that image transformations can affect QR decoding and forensics measurements. More QR samples and controlled experiments are needed before defining reliable detection thresholds.
