package eu.opencloud.android.next.core.sync

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.BitmapShader
import android.graphics.Canvas
import android.graphics.Matrix
import android.graphics.Paint
import android.graphics.Shader
import android.graphics.drawable.AdaptiveIconDrawable
import android.graphics.drawable.Icon
import android.net.Uri

enum class FolderIconColor(
    val resource: Int,
) {
    DEFAULT(R.color.folder_icon_default),
    BLUE(R.color.folder_icon_blue),
    GREEN(R.color.folder_icon_green),
    YELLOW(R.color.folder_icon_yellow),
    RED(R.color.folder_icon_red),
    PURPLE(R.color.folder_icon_purple),
    ORANGE(R.color.folder_icon_orange),
    PINK(R.color.folder_icon_pink),
    TEAL(R.color.folder_icon_teal),
    GREY(R.color.folder_icon_grey),
}

object FolderShortcutIcon {
    fun render(
        context: Context,
        color: FolderIconColor = FolderIconColor.DEFAULT,
        image: Bitmap? = null,
    ): Bitmap {
        val bitmap = Bitmap.createBitmap(216, 216, Bitmap.Config.ARGB_8888)
        val canvas = Canvas(bitmap)
        if (image == null) {
            canvas.drawColor(context.getColor(R.color.folder_shortcut_background))
            val folder = requireNotNull(context.getDrawable(R.drawable.folder_shortcut_foreground)).mutate()
            folder.setTint(context.getColor(color.resource))
            folder.setBounds(0, 0, 216, 216)
            folder.draw(canvas)
        } else {
            val visible = 216f / (1f + 2f * AdaptiveIconDrawable.getExtraInsetFraction())
            val scale = maxOf(visible / image.width, visible / image.height)
            val matrix =
                Matrix().apply {
                    setScale(scale, scale)
                    postTranslate((216f - image.width * scale) / 2, (216f - image.height * scale) / 2)
                }
            val shader =
                BitmapShader(image, Shader.TileMode.CLAMP, Shader.TileMode.CLAMP).apply {
                    setLocalMatrix(matrix)
                }
            val paint = Paint(Paint.ANTI_ALIAS_FLAG or Paint.FILTER_BITMAP_FLAG).apply { this.shader = shader }
            canvas.drawColor(context.getColor(R.color.folder_shortcut_background))
            canvas.drawRect(0f, 0f, 216f, 216f, paint)
        }
        return bitmap
    }

    // Adaptive layers extend outside the visible mask; preview only the visible crop.
    fun preview(
        context: Context,
        color: FolderIconColor,
        image: Bitmap?,
    ): Bitmap {
        val layer = render(context, color, image)
        if (image == null) return layer
        val visible = (layer.width / (1f + 2f * AdaptiveIconDrawable.getExtraInsetFraction())).toInt()
        val inset = (layer.width - visible) / 2
        return Bitmap.createBitmap(layer, inset, inset, visible, visible)
    }

    fun launcherIcon(
        context: Context,
        bitmap: Bitmap?,
    ): Icon =
        if (bitmap == null) {
            Icon.createWithResource(context, R.mipmap.ic_folder_shortcut)
        } else {
            Icon.createWithAdaptiveBitmap(bitmap)
        }

    fun readImage(
        context: Context,
        uri: Uri,
    ): Bitmap {
        val bytes =
            requireNotNull(context.contentResolver.openInputStream(uri)).use { input ->
                val output = java.io.ByteArrayOutputStream()
                val buffer = ByteArray(8192)
                var count = input.read(buffer)
                while (count >= 0) {
                    require(output.size() + count <= 16 * 1024 * 1024)
                    output.write(buffer, 0, count)
                    count = input.read(buffer)
                }
                output.toByteArray()
            }
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeByteArray(bytes, 0, bytes.size, bounds)
        require(bounds.outWidth > 0 && bounds.outHeight > 0)
        var sample = 1
        while (bounds.outWidth / sample > 512 || bounds.outHeight / sample > 512) sample *= 2
        return requireNotNull(
            BitmapFactory.decodeByteArray(
                bytes,
                0,
                bytes.size,
                BitmapFactory.Options().apply {
                    inSampleSize =
                        sample
                },
            ),
        )
    }
}
