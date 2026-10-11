
import cv2
import numpy as np


def analyze_finder_regions(image, points):
    """
    Measure dark-pixel density near three approximate QR corners.

    This is a heuristic, not a definitive finder-pattern
    or tampering detector.
    """

    # Validate the image.
    if (
        image is None
        or not isinstance(image, np.ndarray)
        or image.size == 0
        or image.ndim not in (2, 3)
    ):
        return {
            "success": False,
            "error": "Invalid or empty image",
            "regions": {}
        }

    # Validate the detected corner points.
    try:
        corners_array = np.asarray(points, dtype=np.float32)

        if corners_array.size != 8:
            raise ValueError

        corners = corners_array.reshape(4, 2)

        if not np.isfinite(corners).all():
            raise ValueError

    except (TypeError, ValueError):
        return {
            "success": False,
            "error": "Invalid QR corner points",
            "regions": {}
        }

    # Convert the image to grayscale.
    if image.ndim == 2:
        gray = image
    elif image.shape[2] == 3:
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    elif image.shape[2] == 4:
        gray = cv2.cvtColor(image, cv2.COLOR_BGRA2GRAY)
    else:
        return {
            "success": False,
            "error": "Unsupported image format",
            "regions": {}
        }

    # OpenCV corner order: top-left, top-right,
    # bottom-right, bottom-left.
    top_left = corners[0]
    top_right = corners[1]
    bottom_left = corners[3]

    width = int(np.ptp(corners[:, 0]))
    height = int(np.ptp(corners[:, 1]))

    if width <= 0 or height <= 0:
        return {
            "success": False,
            "error": "Invalid QR geometry",
            "regions": {}
        }

    region_width = max(1, width // 4)
    region_height = max(1, height // 4)

    image_height, image_width = gray.shape

    candidate_corners = {
        "top_left": top_left,
        "top_right": top_right,
        "bottom_left": bottom_left
    }

    regions = {}

    for name, corner in candidate_corners.items():
        x, y = map(int, corner)

        if name == "top_left":
            x1, x2 = x, x + region_width
            y1, y2 = y, y + region_height
        elif name == "top_right":
            x1, x2 = x - region_width, x
            y1, y2 = y, y + region_height
        else:
            x1, x2 = x, x + region_width
            y1, y2 = y - region_height, y

        # Clamp coordinates to image boundaries.
        x1 = max(0, min(x1, image_width))
        x2 = max(0, min(x2, image_width))
        y1 = max(0, min(y1, image_height))
        y2 = max(0, min(y2, image_height))

        crop = gray[y1:y2, x1:x2]

        if crop.size == 0:
            regions[name] = {
                "dark_pixel_density": None,
                "error": "Empty candidate region"
            }
            continue

        dark_pixels = int(np.count_nonzero(crop < 128))
        total_pixels = int(crop.size)

        regions[name] = {
            "dark_pixel_density": round(
                dark_pixels / total_pixels, 3
            ),
            "region_width": int(crop.shape[1]),
            "region_height": int(crop.shape[0])
        }

    return {
        "success": True,
        "error": None,
        "regions": regions
    }
