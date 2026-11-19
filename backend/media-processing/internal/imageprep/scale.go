package imageprep

import (
	"context"
	"image"
	"image/color"
)

type orientedImage struct {
	source      image.Image
	orientation int
}

func (o orientedImage) ColorModel() color.Model {
	return o.source.ColorModel()
}

func (o orientedImage) Bounds() image.Rectangle {
	b := o.source.Bounds()

	if o.orientation >= 5 {
		return image.Rect(0, 0, b.Dy(), b.Dx())
	}

	return image.Rect(0, 0, b.Dx(), b.Dy())
}

func (o orientedImage) At(x, y int) color.Color {
	b := o.source.Bounds()
	w, h := b.Dx(), b.Dy()

	switch o.orientation {
	case 2:
		x = w - 1 - x
	case 3:
		x, y = w-1-x, h-1-y
	case 4:
		y = h - 1 - y
	case 5:
		x, y = y, x
	case 6:
		x, y = y, h-1-x
	case 7:
		x, y = w-1-y, h-1-x
	case 8:
		x, y = w-1-y, x
	}

	return o.source.At(b.Min.X+x, b.Min.Y+y)
}

func scale(ctx context.Context, dst *image.RGBA, src image.Image) error {
	width, height := dst.Bounds().Dx(), dst.Bounds().Dy()
	sw, sh := src.Bounds().Dx(), src.Bounds().Dy()

	for y := 0; y < height; y++ {
		if err := ctx.Err(); err != nil {
			return err
		}

		y0, y1 := y*sh/height, (y+1)*sh/height

		for x := 0; x < width; x++ {
			x0, x1 := x*sw/width, (x+1)*sw/width
			var red, green, blue, alpha uint64
			count := uint64((x1 - x0) * (y1 - y0))

			for sy := y0; sy < y1; sy++ {
				for sx := x0; sx < x1; sx++ {
					r, g, b, a := src.At(sx, sy).RGBA()
					red += uint64(r)
					green += uint64(g)
					blue += uint64(b)
					alpha += uint64(a)
				}
			}

			dst.SetRGBA64(x, y, color.RGBA64{
				R: uint16(red / count),
				G: uint16(green / count),
				B: uint16(blue / count),
				A: uint16(alpha / count),
			})
		}
	}

	return nil
}
