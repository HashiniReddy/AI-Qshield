# Day 5 — QR Image Quality Experiment

## Objective

Evaluate image sharpness and grayscale contrast using OpenCV to understand how image quality changes across clean, blurred, and cropped QR images.

## Method

The AI-QShield image-quality analyzer calculates:

- **Sharpness:** Variance of the Laplacian.
- **Contrast:** Standard deviation of grayscale pixel intensities.
- **Dimensions:** Image width and height in pixels.

## Results

| Image | Dimensions | Sharpness | Contrast |
|---|---|---:|---:|
| Clean QR | 330 × 330 | 8213.81 | 116.05 |
| Blurred QR | 330 × 330 | 107.07 | 100.72 |
| Cropped QR | 264 × 264 | 9835.48 | 122.68 |

## Observations

1. The blurred image has substantially lower sharpness than the clean image.
2. The cropped image has a higher sharpness score than the clean image, demonstrating that sharpness does not directly measure cropping.
3. Contrast differs between the images, but it is not a reliable standalone security indicator.
4. Image-quality measurements should be combined with QR decoding results and other security evidence.

## Limitations

Results depend on image dimensions, preprocessing, compression, and the specific blur or crop operation. These measurements do not establish whether a QR code is malicious or physically tampered with.

## Conclusion

The experiment demonstrates that Laplacian variance can help characterize blur in the tested QR images. AI-QShield will treat these measurements as supporting forensic evidence rather than a standalone maliciousness score.