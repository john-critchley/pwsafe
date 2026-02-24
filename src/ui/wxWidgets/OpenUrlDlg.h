/*
* Copyright (c) 2003-2026 Rony Shapiro <ronys@pwsafe.org>.
* All rights reserved. Use of the code is allowed under the
* Artistic License 2.0 terms, as specified in the LICENSE file
* distributed with this code, or available from
* http://www.opensource.org/licenses/artistic-license-2.0.php
*/

/** \file OpenUrlDlg.h
 * Dialog for opening a password database via a transport URL.
 * Shows an editable combo box pre-populated with recently used URLs.
 */

#ifndef _OPENURLDLG_H_
#define _OPENURLDLG_H_

#include <wx/dialog.h>
#include <wx/combobox.h>
#include <wx/arrstr.h>

class OpenUrlDlg : public wxDialog
{
public:
  OpenUrlDlg(wxWindow *parent, const wxArrayString &recentUrls);

  wxString GetURL() const;

private:
  void CreateControls(const wxArrayString &recentUrls);
  void OnOkClick(wxCommandEvent &evt);

  wxComboBox *m_urlCtrl = nullptr;

  DECLARE_EVENT_TABLE()
};

#endif // _OPENURLDLG_H_
