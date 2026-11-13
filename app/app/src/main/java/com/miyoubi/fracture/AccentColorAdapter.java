package com.miyoubi.fracture;

import android.content.Context;
import android.graphics.drawable.Drawable;
import android.util.TypedValue;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.Filter;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.util.ArrayList;
import java.util.Arrays;

final class AccentColorAdapter extends ArrayAdapter<String> {
    private final String[] labels;
    private final String[] values;
    private final int iconSize;
    private final int iconPad;

    AccentColorAdapter(@NonNull Context context, String[] labels, String[] values) {
        super(context, android.R.layout.simple_list_item_1, new ArrayList<>(Arrays.asList(labels)));
        this.labels = labels.clone();
        this.values = values;
        float d = context.getResources().getDisplayMetrics().density;
        this.iconSize = (int) (20 * d);
        this.iconPad = (int) (16 * d);
    }

    String valueAt(int position) {
        return (position >= 0 && position < values.length) ? values[position] : ThemeHelper.ACCENT_PURPLE;
    }

    @NonNull
    @Override
    public Filter getFilter() {
        return new Filter() {
            @Override
            protected FilterResults performFiltering(CharSequence constraint) {
                FilterResults results = new FilterResults();
                results.values = Arrays.asList(labels);
                results.count = labels.length;
                return results;
            }

            @Override
            protected void publishResults(CharSequence constraint, FilterResults results) {
                clear();
                addAll(labels);
                notifyDataSetChanged();
            }
        };
    }

    @NonNull
    @Override
    public View getView(int position, @Nullable View convertView, @NonNull ViewGroup parent) {
        TextView tv = (TextView) super.getView(position, convertView, parent);
        bind(tv, position);
        return tv;
    }

    @Override
    public View getDropDownView(int position, @Nullable View convertView, @NonNull ViewGroup parent) {
        TextView tv = (TextView) super.getDropDownView(position, convertView, parent);
        bind(tv, position);
        return tv;
    }

    private void bind(TextView tv, int position) {
        String v = valueAt(position);
        Drawable icon = ThemeHelper.makeCircle(ThemeHelper.accentColor(v), iconSize);
        icon.setBounds(0, 0, iconSize, iconSize);
        tv.setCompoundDrawables(icon, null, null, null);
        tv.setCompoundDrawablePadding(iconPad);
        TypedValue out = new TypedValue();
        if (tv.getContext().getTheme().resolveAttribute(
                com.google.android.material.R.attr.colorOnSurface, out, true)) {
            tv.setTextColor(out.data);
        }
    }
}
