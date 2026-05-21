/*
* Copyright (c) 2003-2026 Rony Shapiro <ronys@pwsafe.org>.
* All rights reserved. Use of the code is allowed under the
* Artistic License 2.0 terms, as specified in the LICENSE file
* distributed with this code, or available from
* http://www.opensource.org/licenses/artistic-license-2.0.php
*/

/** \file OpenUrlDlg.cpp
 * Dialog for opening a password database via a transport URL.
 */

#include "OpenUrlDlg.h"

#include <wx/button.h>
#include <wx/sizer.h>
#include <wx/stattext.h>
#include <wx/utils.h>

BEGIN_EVENT_TABLE(OpenUrlDlg, wxDialog)
  EVT_BUTTON(wxID_OK, OpenUrlDlg::OnOkClick)
END_EVENT_TABLE()

OpenUrlDlg::OpenUrlDlg(wxWindow *parent, const wxArrayString &recentUrls)
  : wxDialog(parent, wxID_ANY, _("Open URL"),
             wxDefaultPosition, wxDefaultSize,
             wxDEFAULT_DIALOG_STYLE | wxRESIZE_BORDER)
{
  CreateControls(recentUrls);
  GetSizer()->Fit(this);
  GetSizer()->SetSizeHints(this);
  Centre();
}

void OpenUrlDlg::CreateControls(const wxArrayString &recentUrls)
{
  auto *outer = new wxBoxSizer(wxVERTICAL);

  // URL row
  auto *row = new wxBoxSizer(wxHORIZONTAL);
  row->Add(new wxStaticText(this, wxID_ANY, _("URL:")),
           0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 6);

  m_urlCtrl = new wxComboBox(this, wxID_ANY, wxEmptyString,
                              wxDefaultPosition, wxSize(420, -1),
                              recentUrls, wxCB_DROPDOWN);
  wxString defaultUrl;
  if (wxGetEnv(wxT("DEFAULT_URL"), &defaultUrl) && !defaultUrl.IsEmpty())
    m_urlCtrl->SetValue(defaultUrl);
  else if (!recentUrls.IsEmpty())
    m_urlCtrl->SetValue(recentUrls[0]);
  row->Add(m_urlCtrl, 1, wxEXPAND);

  outer->Add(row, 0, wxEXPAND | wxALL, 12);

  // Button row
  outer->Add(CreateButtonSizer(wxOK | wxCANCEL), 0,
             wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 12);

  SetSizer(outer);
  m_urlCtrl->SetFocus();
}

wxString OpenUrlDlg::GetURL() const
{
  return m_urlCtrl ? m_urlCtrl->GetValue().Trim().Trim(false) : wxString{};
}

void OpenUrlDlg::OnOkClick(wxCommandEvent & WXUNUSED(evt))
{
  if (GetURL().IsEmpty()) {
    m_urlCtrl->SetFocus();
    return;
  }
  EndModal(wxID_OK);
}
