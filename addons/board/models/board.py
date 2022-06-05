# -*- coding: utf-8 -*-
# Part of Odoo. See LICENSE file for full copyright and licensing details.

from odoo import api, models


class Board(models.Model):
    _name = 'board.board'
    _description = "Board"
    _auto = False

    @api.model
    def create(self, vals):
        return self

    @api.model
    def fields_view_get(self, view_id=None, view_type='form', toolbar=False, submenu=False):
        """
        Overrides orm field_view_get.
        @return: Dictionary of Fields, arch and toolbar.
        """

        res = super(Board, self).fields_view_get(view_id=view_id, view_type=view_type, toolbar=toolbar, submenu=submenu)

        if custom_view := self.env['ir.ui.view.custom'].search(
            [('user_id', '=', self.env.uid), ('ref_id', '=', view_id)], limit=1
        ):
            res.update({'custom_view_id': custom_view.id,
                        'arch': custom_view.arch})
        res.update({
            'arch': self._arch_preprocessing(res['arch']),
            'toolbar': {'print': [], 'action': [], 'relate': []}
        })
        return res

    @api.model
    def _arch_preprocessing(self, arch):
        from lxml import etree

        def remove_unauthorized_children(node):
            for child in node.iterchildren():
                if child.tag == 'action' and child.get('invisible'):
                    node.remove(child)
                else:
                    child = remove_unauthorized_children(child)
            return node

        def encode(s):
            return s.encode('utf8') if isinstance(s, unicode) else s

        archnode = etree.fromstring(encode(arch))
        return etree.tostring(remove_unauthorized_children(archnode), pretty_print=True)
