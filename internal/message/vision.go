package message

import (
	"bytes"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
)

type visionSelection struct {
	images  []Image
	omitted int
}

func selectVisionImages(content extractedContent, options VisionOptions) visionSelection {
	switch options.Mode {
	case "always":
	case "fallback":
		if content.ConfidentVisibleChars >= options.MinTextChars {
			return visionSelection{}
		}
	default:
		return visionSelection{}
	}
	if options.MaxImages < 1 || options.MaxBytes < 1 || options.MaxPixels < 1 {
		return visionSelection{omitted: len(content.Images)}
	}
	referenced := make(map[string]bool, len(content.ImageRefs))
	for _, ref := range content.ImageRefs {
		if ref != "" {
			referenced[ref] = true
		}
	}
	result := visionSelection{images: make([]Image, 0, min(options.MaxImages, len(content.Images)))}
	// Prefer images explicitly referenced by the message body, then fill any
	// remaining slots with other embedded images. Some mail clients assign a
	// Content-ID even to ordinary attachments, so an unreferenced ID is not a
	// reliable reason to omit an image.
	for _, wantReferenced := range []bool{true, false} {
		for _, candidate := range content.Images {
			if referenced[candidate.ContentID] != wantReferenced {
				continue
			}
			if len(result.images) >= options.MaxImages {
				result.omitted++
				continue
			}
			if image, ok := visionImage(candidate, options); ok {
				result.images = append(result.images, image)
			} else {
				result.omitted++
			}
		}
	}
	return result
}

func visionImage(candidate extractedImage, options VisionOptions) (Image, bool) {
	if int64(len(candidate.Data)) > options.MaxBytes {
		return Image{}, false
	}
	imageConfig, format, err := image.DecodeConfig(bytes.NewReader(candidate.Data))
	if err != nil || imageConfig.Width < 1 || imageConfig.Height < 1 || int64(imageConfig.Width) > options.MaxPixels/int64(imageConfig.Height) {
		return Image{}, false
	}
	mediaType := map[string]string{"jpeg": "image/jpeg", "png": "image/png", "gif": "image/gif"}[format]
	if mediaType == "" {
		return Image{}, false
	}
	return Image{MediaType: mediaType, Data: candidate.Data}, true
}
