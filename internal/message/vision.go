package message

import (
	"bytes"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"strings"
)

func selectVisionImages(content extractedContent, options VisionOptions) []Image {
	if options.Mode == "off" || options.MaxImages < 1 || options.MaxBytes < 1 || options.MaxPixels < 1 {
		return nil
	}
	if options.Mode == "fallback" && len([]rune(strings.TrimSpace(content.VisibleText))) >= options.MinTextChars {
		return nil
	}
	referenced := make(map[string]bool, len(content.ImageRefs))
	for _, ref := range content.ImageRefs {
		if ref != "" {
			referenced[ref] = true
		}
	}
	selected := make([]Image, 0, min(options.MaxImages, len(content.Images)))
	// Prefer images explicitly referenced by the message body, then fill any
	// remaining slots with other embedded images. Some mail clients assign a
	// Content-ID even to ordinary attachments, so an unreferenced ID is not a
	// reliable reason to omit an image.
	for _, wantReferenced := range []bool{true, false} {
		for _, candidate := range content.Images {
			if len(selected) >= options.MaxImages {
				return selected
			}
			if referenced[candidate.ContentID] != wantReferenced {
				continue
			}
			if image, ok := visionImage(candidate, options); ok {
				selected = append(selected, image)
			}
		}
	}
	return selected
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
